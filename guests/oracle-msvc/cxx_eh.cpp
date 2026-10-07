// Windows-oracle probe: MSVC C++ exceptions and SEH through VCRUNTIME140
// (_CxxThrowException, __CxxFrameHandler3, __C_specific_handler). Throws
// by type, catches by value/reference/catch-all, rethrows, throws from catch
// blocks, unwinds destructors, and runs __try/__except/__finally around
// hardware and software exceptions. Built by guests/build-msvc-oracle.sh.
#include <cstdio>
#include <stdexcept>
#include <string>
#include <typeinfo>
#include <windows.h>

static int alive = 0;
struct Tracked {
    const char* name;
    Tracked(const char* n) : name(n) { alive++; }
    ~Tracked() { alive--; printf("dtor: %s\n", name); }
};
struct Base { virtual ~Base() {} virtual const char* what() const { return "base"; } };
struct Derived : Base {
    std::string message;
    Derived(std::string m) : message(m) {}
    Derived(const Derived& other) : message(other.message + "+copy") {}
    const char* what() const override { return message.c_str(); }
};

__declspec(noinline) void thrower(int kind) {
    Tracked t("thrower");
    if (kind == 0) throw std::runtime_error("runtime");
    if (kind == 1) throw Derived("derived");
    if (kind == 2) throw 42;
    if (kind == 3) throw "text";
}

__declspec(noinline) void level() {
    Tracked outer("level.outer");
    try { Tracked inside("level.try"); thrower(0); }
    catch (std::exception& e) {
        Tracked in_catch("level.catch");
        printf("level.caught: %s\n", e.what());
        throw std::logic_error("second");
    }
}

static int filter_calls = 0;
static int filter(unsigned code) {
    filter_calls++;
    return code == EXCEPTION_INT_DIVIDE_BY_ZERO ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH;
}
__declspec(noinline) int divide(volatile int a, volatile int b) { return a / b; }
// Faults raised by calls: /EHsc SEH covers calls inside __try, not faulting
// instructions in the __try body itself (that needs /EHa).
__declspec(noinline) void store(volatile int* p) { *p = 1; }

static void seh() {
    __try { divide(1, 0); printf("seh.divide: not caught\n"); }
    __except (filter(GetExceptionCode())) { printf("seh.divide: caught filter_calls=%d\n", filter_calls); }
    __try {
        __try { RaiseException(0xE0001234, 0, 0, nullptr); }
        __finally { printf("seh.finally: abnormal=%d\n", AbnormalTermination()); }
    }
    __except (GetExceptionCode() == 0xE0001234 ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) {
        printf("seh.custom: caught\n");
    }
    __try { store(nullptr); }
    __except (GetExceptionCode() == EXCEPTION_ACCESS_VIOLATION) { printf("seh.access_violation: caught\n"); }
}

// RTTI: single and multiple inheritance, virtual bases.
struct RA { virtual ~RA() {} int a = 1; };
struct RB : RA { int b = 2; };
struct RC { virtual ~RC() {} int c = 3; };
struct RD : RB, RC { int d = 4; };
struct RV { virtual ~RV() {} int v = 5; };
struct RL : virtual RV { int l = 6; };
struct RR : virtual RV { int r = 7; };
struct RVD : RL, RR { int vd = 8; };

static void rtti() {
    RD* d = new RD;
    RA* as_a = d;
    printf("rtti.downcast: %d\n", dynamic_cast<RD*>(as_a) == d);
    RC* as_c = dynamic_cast<RC*>(as_a);
    printf("rtti.crosscast: %d %d\n", as_c == static_cast<RC*>(d), as_c ? as_c->c : -1);
    printf("rtti.to_void: %d\n", dynamic_cast<void*>(as_c) == static_cast<void*>(d));
    RA* plain = new RA;
    printf("rtti.failed_pointer: %d\n", dynamic_cast<RB*>(plain) == nullptr);
    try {
        (void)dynamic_cast<RB&>(*plain);
        printf("rtti.failed_reference: not thrown\n");
    } catch (const std::bad_cast&) {
        printf("rtti.failed_reference: bad_cast\n");
    }
    RV* v = new RVD;
    RR* as_r = dynamic_cast<RR*>(v);
    printf("rtti.virtual_base: %d\n", as_r ? as_r->r : -1);
    printf("rtti.virtual_down: %d\n", dynamic_cast<RVD*>(v) ? dynamic_cast<RVD*>(v)->vd : -1);
    printf("rtti.typeid: %d\n", typeid(*as_a) == typeid(RD));
    RA* none = nullptr;
    try {
        (void)typeid(*none).name();
        printf("rtti.typeid_null: not thrown\n");
    } catch (const std::bad_typeid&) {
        printf("rtti.typeid_null: bad_typeid\n");
    }
    delete d;
    delete plain;
    delete v;
}

static void run() {
    Tracked keep("run.keep");
    try { thrower(0); } catch (const std::exception& e) { printf("catch.std_exception: %s\n", e.what()); }
    try { thrower(1); } catch (Base b) { printf("catch.by_value_slices: %s\n", b.what()); }
    try { thrower(1); } catch (const Derived& d) { printf("catch.by_reference: %s\n", d.what()); }
    try { thrower(2); } catch (const char*) { printf("catch.order: wrong\n"); } catch (int v) { printf("catch.order: int %d\n", v); }
    try { thrower(3); } catch (...) { printf("catch.all: ok\n"); }
    try { try { thrower(2); } catch (int) { printf("rethrow: inner\n"); throw; } } catch (int v) { printf("rethrow: outer %d\n", v); }
    try { level(); } catch (std::logic_error& e) { printf("from_catch: %s alive=%d\n", e.what(), alive); }
    try { try { throw 1; } catch (int) { try { throw 2; } catch (int v) { printf("nested_catch: %d\n", v); } throw; } }
    catch (int v) { printf("nested_rethrow: %d\n", v); }
    seh();
    rtti();
    try { thrower(2); } catch (int) { printf("after_seh: catch ok\n"); }
    printf("alive: %d\n", alive);
}

int main() {
    printf("probe cxx_eh\n");
    run();
    printf("after_run: alive=%d\n", alive);
    printf("END\n");
    fflush(stdout);
    return 0;
}
