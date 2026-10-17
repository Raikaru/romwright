//! Offscreen rendering: the same egui frame the window shows, rendered by
//! `egui_wgpu::Renderer` into a wgpu texture with no window or display, then
//! read back for PNG output. The gate and `--screenshot` both drive the app
//! through [`Driver`], so CI needs a GPU or a software Vulkan adapter
//! (lavapipe), never a display server.

use crate::app::DesktopApp;
use egui_wgpu::{Renderer, RendererOptions, ScreenDescriptor};
use std::path::Path;
use std::time::Instant;

const FORMAT: wgpu::TextureFormat = wgpu::TextureFormat::Rgba8UnormSrgb;

pub struct Offscreen {
    device: wgpu::Device,
    queue: wgpu::Queue,
    renderer: Renderer,
    texture: wgpu::Texture,
    view: wgpu::TextureView,
    width: u32,
    height: u32,
    pub adapter: String,
}

impl Offscreen {
    /// Picks a hardware adapter when one exists, else the fallback
    /// (software) adapter.
    pub fn new(width: u32, height: u32) -> Result<Self, String> {
        let instance = wgpu::Instance::new(wgpu::InstanceDescriptor {
            backends: wgpu::Backends::PRIMARY,
            ..wgpu::InstanceDescriptor::new_without_display_handle()
        });
        let adapter = [false, true]
            .into_iter()
            .find_map(|fallback| {
                pollster::block_on(instance.request_adapter(&wgpu::RequestAdapterOptions {
                    power_preference: wgpu::PowerPreference::LowPower,
                    force_fallback_adapter: fallback,
                    compatible_surface: None,
                    apply_limit_buckets: false,
                }))
                .ok()
            })
            .ok_or("no wgpu adapter: install a Vulkan/Metal/DX12 driver or a software adapter such as lavapipe")?;
        let info = adapter.get_info();
        let (device, queue) = pollster::block_on(adapter.request_device(&wgpu::DeviceDescriptor {
            label: Some("romwright-offscreen"),
            required_limits: wgpu::Limits::downlevel_defaults().using_resolution(adapter.limits()),
            ..Default::default()
        }))
        .map_err(|error| format!("wgpu device: {error}"))?;
        let texture = device.create_texture(&wgpu::TextureDescriptor {
            label: Some("romwright-frame"),
            size: wgpu::Extent3d { width, height, depth_or_array_layers: 1 },
            mip_level_count: 1,
            sample_count: 1,
            dimension: wgpu::TextureDimension::D2,
            format: FORMAT,
            usage: wgpu::TextureUsages::RENDER_ATTACHMENT | wgpu::TextureUsages::COPY_SRC,
            view_formats: &[],
        });
        let view = texture.create_view(&wgpu::TextureViewDescriptor::default());
        let renderer = Renderer::new(&device, FORMAT, RendererOptions::default());
        Ok(Self {
            device,
            queue,
            renderer,
            texture,
            view,
            width,
            height,
            adapter: format!("{} ({:?})", info.name, info.backend),
        })
    }

    /// Renders one egui output into the frame texture and waits for the GPU.
    pub fn render(&mut self, context: &egui::Context, mut output: egui::FullOutput) {
        let mut textures = std::mem::take(&mut output.textures_delta);
        for (id, deltas) in &textures.set {
            for delta in deltas {
                self.renderer.update_texture(&self.device, &self.queue, *id, delta);
            }
        }
        let primitives = context.tessellate(output.shapes, output.pixels_per_point);
        let screen = ScreenDescriptor { size_in_pixels: [self.width, self.height], pixels_per_point: output.pixels_per_point };
        let mut encoder = self.device.create_command_encoder(&wgpu::CommandEncoderDescriptor { label: Some("romwright-frame") });
        let mut buffers = self.renderer.update_buffers(&self.device, &self.queue, &mut encoder, &primitives, &screen);
        {
            let pass = encoder.begin_render_pass(&wgpu::RenderPassDescriptor {
                label: Some("romwright-egui"),
                color_attachments: &[Some(wgpu::RenderPassColorAttachment {
                    view: &self.view,
                    resolve_target: None,
                    depth_slice: None,
                    ops: wgpu::Operations { load: wgpu::LoadOp::Clear(wgpu::Color::BLACK), store: wgpu::StoreOp::Store },
                })],
                ..Default::default()
            });
            let mut pass = pass.forget_lifetime();
            self.renderer.render(&mut pass, &primitives, &screen);
        }
        buffers.push(encoder.finish());
        self.queue.submit(buffers);
        for id in &textures.free {
            self.renderer.free_texture(id);
        }
        textures.clear();
        let _ = self.device.poll(wgpu::PollType::wait_indefinitely());
    }

    /// Reads the frame back as tightly packed RGBA8 (sRGB).
    pub fn read_rgba(&self) -> Result<Vec<u8>, String> {
        let row = self.width as usize * 4;
        let align = wgpu::COPY_BYTES_PER_ROW_ALIGNMENT as usize;
        let padded = row.div_ceil(align) * align;
        let buffer = self.device.create_buffer(&wgpu::BufferDescriptor {
            label: Some("romwright-readback"),
            size: (padded * self.height as usize) as u64,
            usage: wgpu::BufferUsages::COPY_DST | wgpu::BufferUsages::MAP_READ,
            mapped_at_creation: false,
        });
        let mut encoder = self.device.create_command_encoder(&wgpu::CommandEncoderDescriptor { label: Some("romwright-readback") });
        encoder.copy_texture_to_buffer(
            wgpu::TexelCopyTextureInfo { texture: &self.texture, mip_level: 0, origin: wgpu::Origin3d::ZERO, aspect: wgpu::TextureAspect::All },
            wgpu::TexelCopyBufferInfo {
                buffer: &buffer,
                layout: wgpu::TexelCopyBufferLayout { offset: 0, bytes_per_row: Some(padded as u32), rows_per_image: Some(self.height) },
            },
            wgpu::Extent3d { width: self.width, height: self.height, depth_or_array_layers: 1 },
        );
        self.queue.submit([encoder.finish()]);
        let slice = buffer.slice(..);
        let (sender, receiver) = std::sync::mpsc::channel();
        slice.map_async(wgpu::MapMode::Read, move |result| {
            let _ = sender.send(result);
        });
        let _ = self.device.poll(wgpu::PollType::wait_indefinitely());
        receiver
            .recv()
            .map_err(|_| "readback never completed".to_string())?
            .map_err(|error| format!("readback: {error}"))?;
        let mapped = slice.get_mapped_range().map_err(|error| format!("readback: {error}"))?;
        let mut pixels = Vec::with_capacity(row * self.height as usize);
        for line in mapped.chunks(padded) {
            pixels.extend_from_slice(&line[..row]);
        }
        drop(mapped);
        buffer.unmap();
        Ok(pixels)
    }

    pub fn write_png(&self, path: &Path) -> Result<(), String> {
        let pixels = self.read_rgba()?;
        if let Some(parent) = path.parent().filter(|parent| !parent.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent).map_err(|error| error.to_string())?;
        }
        let file = std::fs::File::create(path).map_err(|error| format!("{}: {error}", path.display()))?;
        let mut encoder = png::Encoder::new(std::io::BufWriter::new(file), self.width, self.height);
        encoder.set_color(png::ColorType::Rgba);
        encoder.set_depth(png::BitDepth::Eight);
        encoder.set_source_srgb(png::SrgbRenderingIntent::Perceptual);
        let mut writer = encoder.write_header().map_err(|error| error.to_string())?;
        writer.write_image_data(&pixels).map_err(|error| error.to_string())
    }
}

/// Runs app frames into the offscreen target.
pub struct Driver {
    pub context: egui::Context,
    pub offscreen: Offscreen,
    started: Instant,
    width: u32,
    height: u32,
    scale: f32,
}

impl Driver {
    pub fn new(width: u32, height: u32, scale: f32) -> Result<Self, String> {
        let pixel_width = (width as f32 * scale).round() as u32;
        let pixel_height = (height as f32 * scale).round() as u32;
        Ok(Self {
            context: egui::Context::default(),
            offscreen: Offscreen::new(pixel_width, pixel_height)?,
            started: Instant::now(),
            width,
            height,
            scale,
        })
    }

    /// One full frame: logic, layout, paint, GPU render.
    pub fn frame(&mut self, app: &mut DesktopApp) {
        let mut input = egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, egui::vec2(self.width as f32, self.height as f32))),
            time: Some(self.started.elapsed().as_secs_f64()),
            focused: true,
            ..Default::default()
        };
        input
            .viewports
            .entry(egui::ViewportId::ROOT)
            .or_default()
            .native_pixels_per_point = Some(self.scale);
        app.prepare(&self.context);
        let output = self.context.run_ui(input, |ui| app.show(ui));
        self.offscreen.render(&self.context, output);
    }

    pub fn save_png(&self, path: &Path) -> Result<(), String> {
        self.offscreen.write_png(path)
    }
}
