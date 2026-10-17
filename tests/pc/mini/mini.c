/* PcProject dev fixture: original code written for this test (no third-party source). */
typedef unsigned char u8; typedef unsigned short u16; typedef unsigned int u32;
typedef struct { float x, y, z; } vec3_t;
typedef struct entity_s { struct entity_s *next; int health; int flags; vec3_t origin; vec3_t vel; char name[16]; } entity_t;
typedef struct { int count; int items[32]; } list_t;

int g_frame; int g_seed = 12345; float g_gravity = 800.0f; entity_t *g_head; list_t g_list; char g_buf[256];
int g_table[8] = {3, 5, 7, 11, 13, 17, 19, 23};

float __cdecl Vec_Dot(const vec3_t *a, const vec3_t *b) { return a->x*b->x + a->y*b->y + a->z*b->z; }
void __cdecl Vec_Add(const vec3_t *a, const vec3_t *b, vec3_t *out) { out->x = a->x+b->x; out->y = a->y+b->y; out->z = a->z+b->z; }
void __cdecl Vec_Scale(const vec3_t *a, float s, vec3_t *out) { out->x = a->x*s; out->y = a->y*s; out->z = a->z*s; }
void __cdecl Vec_Cross(const vec3_t *a, const vec3_t *b, vec3_t *out) {
    out->x = a->y*b->z - a->z*b->y; out->y = a->z*b->x - a->x*b->z; out->z = a->x*b->y - a->y*b->x; }
int __cdecl Rand_Next(void) { g_seed = g_seed * 1103515245 + 12345; return (g_seed >> 16) & 0x7fff; }
int __stdcall Clamp_Int(int v, int lo, int hi) { if (v < lo) return lo; if (v > hi) return hi; return v; }
int __fastcall Fast_Sum(int a, int b, int c) { return a + b * c + g_frame; }
int __stdcall Abs_Diff(int a, int b) { return a > b ? a - b : b - a; }
unsigned int __cdecl Str_Len(const char *s) { const char *p = s; while (*p) p++; return (unsigned int)(p - s); }
int __cdecl Str_Cmp(const char *a, const char *b) {
    while (*a && *a == *b) { a++; b++; } return (int)(u8)*a - (int)(u8)*b; }
char * __cdecl Str_Copy(char *dst, const char *src) { char *d = dst; while ((*d++ = *src++) != 0) ; return dst; }
void __cdecl Mem_Set(void *p, int v, unsigned int n) { u8 *b = (u8 *)p; while (n--) *b++ = (u8)v; }
void __cdecl Mem_Copy(void *d, const void *s, unsigned int n) { u8 *a = (u8 *)d; const u8 *b = (const u8 *)s; while (n--) *a++ = *b++; }
int __cdecl List_Add(list_t *l, int v) { if (l->count >= 32) return -1; l->items[l->count] = v; return l->count++; }
int __cdecl List_Find(const list_t *l, int v) { int i; for (i = 0; i < l->count; i++) if (l->items[i] == v) return i; return -1; }
int __cdecl List_Sum(const list_t *l) { int i, s = 0; for (i = 0; i < l->count; i++) s += l->items[i]; return s; }
void __cdecl List_Remove(list_t *l, int idx) { int i; for (i = idx; i < l->count - 1; i++) l->items[i] = l->items[i+1]; l->count--; }
entity_t * __cdecl Ent_Find(const char *name) { entity_t *e; for (e = g_head; e; e = e->next) if (!Str_Cmp(e->name, name)) return e; return 0; }
void __cdecl Ent_Link(entity_t *e) { e->next = g_head; g_head = e; }
void __cdecl Ent_Unlink(entity_t *e) { entity_t **pp = &g_head; while (*pp) { if (*pp == e) { *pp = e->next; return; } pp = &(*pp)->next; } }
int __cdecl Ent_Damage(entity_t *e, int amount) { e->health -= amount; if (e->health <= 0) { e->flags |= 1; return 1; } return 0; }
void __cdecl Ent_Think(entity_t *e, float dt) {
    vec3_t d; Vec_Scale(&e->vel, dt, &d); Vec_Add(&e->origin, &d, &e->origin); e->vel.z -= g_gravity * dt; }
int __cdecl Ent_Count(void) { int n = 0; entity_t *e; for (e = g_head; e; e = e->next) n++; return n; }
int __cdecl Table_Lookup(int i) { return g_table[i & 7]; }
int __cdecl Op_Eval(int op, int a, int b) {
    switch (op) { case 0: return a + b; case 1: return a - b; case 2: return a * b; case 3: return b ? a / b : 0;
    case 4: return a & b; case 5: return a | b; case 6: return a ^ b; case 7: return a << (b & 31); default: return -1; } }
int __cdecl Day_Name(int d) { switch (d) { case 1: return 'M'; case 2: return 'T'; case 3: return 'W'; case 4: return 'R'; case 5: return 'F'; case 6: return 'S'; case 7: return 'U'; } return '?'; }
unsigned int __cdecl Hash_Str(const char *s) { unsigned int h = 5381; while (*s) h = h * 33 + (u8)*s++; return h; }
int __cdecl Bit_Count(u32 v) { int n = 0; while (v) { n += v & 1; v >>= 1; } return n; }
u32 __cdecl Swap32(u32 v) { return (v >> 24) | ((v >> 8) & 0xff00) | ((v << 8) & 0xff0000) | (v << 24); }
u16 __cdecl Swap16(u16 v) { return (u16)((v >> 8) | (v << 8)); }
int __cdecl Min3(int a, int b, int c) { int m = a; if (b < m) m = b; if (c < m) m = c; return m; }
float __cdecl Lerp(float a, float b, float t) { return a + (b - a) * t; }
float __cdecl Len_Sq(const vec3_t *v) { return Vec_Dot(v, v); }
int __cdecl Fib(int n) { int a = 0, b = 1, i; for (i = 0; i < n; i++) { int t = a + b; a = b; b = t; } return a; }
int __cdecl Gcd(int a, int b) { while (b) { int t = a % b; a = b; b = t; } return a; }
int __cdecl Is_Prime(int n) { int i; if (n < 2) return 0; for (i = 2; i * i <= n; i++) if (n % i == 0) return 0; return 1; }
void __cdecl Buf_Fill(void) { int i; for (i = 0; i < 256; i++) g_buf[i] = (char)(i * 3 + g_frame); }
int __cdecl Buf_Checksum(void) { int i, s = 0; for (i = 0; i < 256; i++) s = (s << 1) ^ g_buf[i]; return s; }
void __cdecl Frame_Tick(void) { g_frame++; if (g_frame > 1000000) g_frame = 0; }
int __cdecl Sort_Items(list_t *l) { int i, j, sw = 0; for (i = 0; i < l->count; i++) for (j = i + 1; j < l->count; j++) if (l->items[j] < l->items[i]) { int t = l->items[i]; l->items[i] = l->items[j]; l->items[j] = t; sw++; } return sw; }
int __cdecl Median3(int a, int b, int c) { if (a > b) { int t = a; a = b; b = t; } if (b > c) b = c; return a > b ? a : b; }
float __cdecl Max_Vec(const vec3_t *v) { float m = v->x; if (v->y > m) m = v->y; if (v->z > m) m = v->z; return m; }
void __cdecl Ent_Init(entity_t *e, const char *name, int hp) { Mem_Set(e, 0, sizeof(*e)); Str_Copy(e->name, name); e->health = hp; Ent_Link(e); }
int __cdecl Ent_Total_Hp(void) { int s = 0; entity_t *e; for (e = g_head; e; e = e->next) s += e->health; return s; }
int __cdecl Parse_Int(const char *s) { int n = 0, neg = 0; if (*s == '-') { neg = 1; s++; } while (*s >= '0' && *s <= '9') n = n * 10 + (*s++ - '0'); return neg ? -n : n; }
int __cdecl Rect_Hit(const int *a, const int *b) { return a[0] < b[2] && a[2] > b[0] && a[1] < b[3] && a[3] > b[1]; }
void __cdecl Rotate_Xy(vec3_t *v, float c, float s) { float x = v->x * c - v->y * s; float y = v->x * s + v->y * c; v->x = x; v->y = y; }
int __stdcall Mix_Args(int a, int b, int c, int d) { return Abs_Diff(a, b) + Abs_Diff(c, d) + Clamp_Int(a + c, 0, 100); }
int __cdecl Dispatch(int idx, int a) { static int (__cdecl *fn[2])(int) = { Table_Lookup, Fib }; return fn[idx & 1](a); }

void __cdecl start(void) { Frame_Tick(); Buf_Fill(); Rand_Next(); Fast_Sum(1,2,3); Mix_Args(1,2,3,4); Dispatch(1, 5); Day_Name(2); Op_Eval(1,2,3); List_Add(&g_list, 3); List_Find(&g_list, 3); List_Sum(&g_list); List_Remove(&g_list,0);
  Ent_Find("a"); Ent_Unlink(0); Ent_Damage(0,1); Ent_Think(0,1.0f); Ent_Count(); Hash_Str("x"); Bit_Count(3); Swap32(1); Swap16(1); Min3(1,2,3); Lerp(1,2,3); Len_Sq(0); Gcd(4,6); Is_Prime(7); Buf_Checksum(); Sort_Items(&g_list); Median3(1,2,3); Max_Vec(0); Ent_Init(0,"a",1); Ent_Total_Hp(); Parse_Int("1"); Rect_Hit(0,0); Rotate_Xy(0,1,0); Vec_Cross(0,0,0); Mem_Copy(0,0,0); Str_Len("a"); }
int _fltused = 0x9875;
