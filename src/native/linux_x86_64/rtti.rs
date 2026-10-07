//! MSVC run-time type information from VCRUNTIME140: `__RTDynamicCast`
//! (`dynamic_cast`), `__RTCastToVoid` (`dynamic_cast<void*>`) and
//! `__RTtypeid` (`typeid` of a polymorphic object), over the RTTI records
//! MSVC and clang-cl emit (complete object locator before each vtable,
//! class hierarchy and base class descriptors). Failures that C++ reports
//! by exception throw `std::bad_cast` / `std::bad_typeid`, built here with
//! the layout and type names of the MSVC STL's classes so guest handlers
//! for them (or for `std::exception`) catch them.

use super::*;

fn read_u32(address: u64) -> u32 {
    unsafe { (address as *const u32).read_unaligned() }
}
fn read_i32(address: u64) -> i32 {
    unsafe { (address as *const i32).read_unaligned() }
}
fn read_u64(address: u64) -> u64 {
    unsafe { (address as *const u64).read_unaligned() }
}

/// A complete object locator: (image base, offset, cdOffset, type
/// descriptor, class hierarchy descriptor).
struct Locator {
    image_base: u64,
    offset: u32,
    cd_offset: u32,
    type_descriptor: u64,
    hierarchy: u64,
}

/// The locator of the object whose vfptr is at `object`.
fn locator(object: u64) -> Option<Locator> {
    let vftable = read_u64(object);
    if vftable == 0 {
        return None;
    }
    let col = read_u64(vftable - 8);
    // x64 locators (signature 1) carry their own RVA, which gives the base.
    if col == 0 || read_u32(col) != 1 {
        return None;
    }
    let image_base = col.wrapping_sub(u64::from(read_u32(col + 20)));
    Some(Locator {
        image_base,
        offset: read_u32(col + 4),
        cd_offset: read_u32(col + 8),
        type_descriptor: image_base + u64::from(read_u32(col + 12)),
        hierarchy: image_base + u64::from(read_u32(col + 16)),
    })
}

/// `FindCompleteObject`: the most-derived object containing `object`.
fn complete_object(object: u64, locator: &Locator) -> u64 {
    let mut complete = object.wrapping_sub(u64::from(locator.offset));
    if locator.cd_offset != 0 {
        let adjust = read_i32(object.wrapping_sub(u64::from(locator.cd_offset)));
        complete = complete.wrapping_sub(adjust as i64 as u64);
    }
    complete
}

fn type_name(descriptor: u64) -> &'static std::ffi::CStr {
    unsafe { std::ffi::CStr::from_ptr((descriptor + 16) as *const _) }
}

fn same_type(a: u64, b: u64) -> bool {
    a == b || (a != 0 && b != 0 && type_name(a) == type_name(b))
}

/// A base class descriptor of the complete object's hierarchy.
#[derive(Clone, Copy)]
struct Base {
    type_descriptor: u64,
    contained: u32,
    displacement: (i32, i32, i32),
    attributes: u32,
}

const BCD_NOTVISIBLE: u32 = 0x1;
const BCD_AMBIGUOUS: u32 = 0x2;
const BCD_PRIVORPROTBASE: u32 = 0x4;

fn bases(locator: &Locator) -> Vec<Base> {
    let count = read_u32(locator.hierarchy + 8);
    let array = locator.image_base + u64::from(read_u32(locator.hierarchy + 12));
    (0..u64::from(count))
        .map(|index| {
            let descriptor = locator.image_base + u64::from(read_u32(array + index * 4));
            Base {
                type_descriptor: locator.image_base + u64::from(read_u32(descriptor)),
                contained: read_u32(descriptor + 4),
                displacement: (
                    read_i32(descriptor + 8),
                    read_i32(descriptor + 12),
                    read_i32(descriptor + 16),
                ),
                attributes: read_u32(descriptor + 20),
            }
        })
        .collect()
}

/// `PMDtoOffset`: where a base sits in the complete object.
fn base_offset(complete: u64, (mdisp, pdisp, vdisp): (i32, i32, i32)) -> i64 {
    let mut offset = mdisp as i64;
    if pdisp >= 0 {
        let vbtable = read_u64(complete.wrapping_add(pdisp as i64 as u64));
        offset += pdisp as i64 + read_i32(vbtable.wrapping_add(vdisp as i64 as u64)) as i64;
    }
    offset
}

/// The `dynamic_cast` target subobject for the source subobject at
/// `source_offset` of `complete`: a downcast when the source lies within a
/// target subobject, else a cross-cast to a public unambiguous base.
fn find_target(
    complete: u64,
    bases: &[Base],
    source_type: u64,
    source_offset: i64,
    target_type: u64,
) -> Option<i64> {
    let source_index = bases.iter().position(|base| {
        same_type(base.type_descriptor, source_type)
            && base_offset(complete, base.displacement) == source_offset
    });
    // Downcast: a target whose contained bases include this source.
    let mut found = None;
    for (index, base) in bases.iter().enumerate() {
        if !same_type(base.type_descriptor, target_type) {
            continue;
        }
        let contains_source = source_index.is_some_and(|source| {
            source > index && source <= index + base.contained as usize
        }) || (source_index == Some(index));
        if contains_source && base.attributes & BCD_NOTVISIBLE == 0 {
            let offset = base_offset(complete, base.displacement);
            if found.is_some_and(|existing| existing != offset) {
                return None; // more than one: ambiguous
            }
            found = Some(offset);
        }
    }
    if found.is_some() {
        return found;
    }
    // Cross-cast: the source must be a public base, the target a public,
    // unambiguous base of the complete object.
    let source_public = source_index.is_some_and(|index| bases[index].attributes & BCD_NOTVISIBLE == 0);
    if !source_public {
        return None;
    }
    bases
        .iter()
        .find(|base| {
            same_type(base.type_descriptor, target_type)
                && base.attributes & (BCD_NOTVISIBLE | BCD_AMBIGUOUS | BCD_PRIVORPROTBASE) == 0
        })
        .map(|base| base_offset(complete, base.displacement))
}

// ---- std::bad_cast / std::bad_typeid -------------------------------------

/// The exception object: a `std::exception` (vfptr, then
/// `__std_exception_data { const char* _What; bool _DoFree; }`).
#[repr(C)]
struct StdException {
    vftable: *const u64,
    what: *const u8,
    do_free: u64,
}

extern "win64" fn exception_destructor(_this: *mut StdException, _flags: u32) -> *mut StdException {
    _this
}
extern "win64" fn exception_what(this: *const StdException) -> *const u8 {
    unsafe { (*this).what }
}
extern "win64" fn exception_unwind(_this: *mut StdException) {}

/// ThrowInfo, catchable types and type descriptors for one exception class
/// and its `std::exception` base, laid out in one block so their RVAs are
/// offsets from the block (the throw's image base).
#[repr(C, align(16))]
struct ThrowBlock {
    throw_info: [u32; 4],
    catchable_array: [u32; 3],
    catchable_types: [[u32; 7]; 2],
    descriptors: [[u8; 48]; 2],
}

fn throw_block(class: &str) -> &'static ThrowBlock {
    static BLOCKS: LazyLock<Mutex<HashMap<String, &'static ThrowBlock>>> =
        LazyLock::new(|| Mutex::new(HashMap::new()));
    let mut blocks = BLOCKS.lock().unwrap();
    if let Some(block) = blocks.get(class) {
        return block;
    }
    let block: &'static mut ThrowBlock = Box::leak(Box::new(ThrowBlock {
        throw_info: [0; 4],
        catchable_array: [0; 3],
        catchable_types: [[0; 7]; 2],
        descriptors: [[0; 48]; 2],
    }));
    let base = block as *const ThrowBlock as u64;
    let rva = |address: u64| (address - base) as u32;
    for (index, name) in [format!(".?AV{class}@std@@"), ".?AVexception@std@@".to_string()]
        .iter()
        .enumerate()
    {
        block.descriptors[index][16..16 + name.len()].copy_from_slice(name.as_bytes());
    }
    for index in 0..2 {
        let descriptor = rva(block.descriptors[index].as_ptr() as u64);
        // properties, type, mdisp, pdisp (-1: not virtual), vdisp, size, copy
        block.catchable_types[index] = [0, descriptor, 0, u32::MAX, 0, 24, 0];
    }
    block.catchable_array = [
        2,
        rva(block.catchable_types[0].as_ptr() as u64),
        rva(block.catchable_types[1].as_ptr() as u64),
    ];
    // attributes, destructor (unused here: objects are leaked), forward
    // compat, catchable array.
    block.throw_info = [0, 0, 0, rva(block.catchable_array.as_ptr() as u64)];
    let _ = exception_unwind;
    blocks.insert(class.to_string(), block);
    block
}

/// Throw `std::<class>` with `message` from the guest frame of `context`.
fn throw_std(class: &str, message: &'static [u8], context: *mut NativeExceptionContext) -> ! {
    // The vtable: scalar deleting destructor, then what().
    static VFTABLE: LazyLock<[u64; 2]> = LazyLock::new(|| {
        [
            exception_destructor as *const () as u64,
            exception_what as *const () as u64,
        ]
    });
    let block = throw_block(class);
    let object = Box::leak(Box::new(StdException {
        vftable: VFTABLE.as_ptr(),
        what: message.as_ptr(),
        do_free: 0,
    }));
    let base = block as *const ThrowBlock as u64;
    let arguments = [
        0x1993_0520,
        object as *mut StdException as u64,
        block.throw_info.as_ptr() as u64,
        base,
    ];
    winrun_raise_exception_with_context(CXX_EXCEPTION, 1, 4, arguments.as_ptr(), context);
    native_exit_process(3)
}

/// `__RTDynamicCast` continued from its assembly entry with the caller's
/// context (for `std::bad_cast`).
#[no_mangle]
extern "win64" fn winrun_rt_dynamic_cast_with_context(
    object: u64,
    vf_delta: i32,
    source_type: u64,
    target_type: u64,
    is_reference: i32,
    context: *mut NativeExceptionContext,
) -> u64 {
    if object == 0 {
        return 0;
    }
    let result = locator(object).and_then(|locator| {
        let complete = complete_object(object, &locator);
        let source = object.wrapping_sub(vf_delta as i64 as u64);
        let source_offset = source.wrapping_sub(complete) as i64;
        find_target(complete, &bases(&locator), source_type, source_offset, target_type)
            .map(|offset| complete.wrapping_add(offset as u64))
    });
    match result {
        Some(target) => target,
        None if is_reference != 0 => throw_std("bad_cast", b"Bad dynamic_cast!\0", context),
        None => 0,
    }
}

/// `__RTCastToVoid`: the most-derived object.
pub(super) extern "win64" fn native_rt_cast_to_void(object: u64) -> u64 {
    if object == 0 {
        return 0;
    }
    locator(object).map_or(0, |locator| complete_object(object, &locator))
}

/// `__RTtypeid` continued from its assembly entry: the dynamic type's
/// descriptor, or `std::bad_typeid` for a null object.
#[no_mangle]
extern "win64" fn winrun_rt_typeid_with_context(object: u64, context: *mut NativeExceptionContext) -> u64 {
    if object == 0 {
        throw_std("bad_typeid", b"Attempted a typeid of nullptr pointer!\0", context);
    }
    locator(object).map_or(0, |locator| locator.type_descriptor)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fake image holding RTTI for `D : B, C` where `B : A`: bases in
    /// MSVC order (complete object first, contained bases after each).
    struct Image {
        bytes: Vec<u8>,
    }

    impl Image {
        fn base(&self) -> u64 {
            self.bytes.as_ptr() as u64
        }
        fn put(&mut self, at: usize, value: u32) {
            self.bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
        }
        fn name(&mut self, at: usize, name: &str) {
            self.bytes[at + 16..at + 16 + name.len()].copy_from_slice(name.as_bytes());
        }
    }

    #[test]
    fn casts_follow_the_base_class_descriptors() {
        let mut image = Image { bytes: vec![0; 0x1000] };
        // Type descriptors at 0x100 (D), 0x140 (B), 0x180 (A), 0x1c0 (C), 0x200 (X).
        for (at, name) in [(0x100, ".?AUD@@"), (0x140, ".?AUB@@"), (0x180, ".?AUA@@"), (0x1c0, ".?AUC@@"), (0x200, ".?AUX@@")] {
            image.name(at, name);
        }
        // Base class descriptors at 0x300.. (28 bytes): D(contains 3), B(1), A(0) at 0, C(0) at 16.
        for (index, (descriptor, contained, mdisp)) in [(0x100u32, 3u32, 0i32), (0x140, 1, 0), (0x180, 0, 0), (0x1c0, 0, 16)].into_iter().enumerate() {
            let at = 0x300 + index * 28;
            image.put(at, descriptor);
            image.put(at + 4, contained);
            image.put(at + 8, mdisp as u32);
            image.put(at + 12, u32::MAX); // pdisp -1
        }
        // Base class array at 0x400, hierarchy at 0x420 (multiple inheritance).
        for index in 0..4 {
            image.put(0x400 + index * 4, (0x300 + index * 28) as u32);
        }
        image.put(0x424, 1);
        image.put(0x428, 4);
        image.put(0x42c, 0x400);
        // Locators: D's primary vftable at 0x500 (offset 0), C-in-D's at 0x520 (offset 16).
        for (col, offset) in [(0x440usize, 0u32), (0x460, 16)] {
            image.put(col, 1);
            image.put(col + 4, offset);
            image.put(col + 12, 0x100);
            image.put(col + 16, 0x420);
            image.put(col + 20, col as u32);
        }
        let base = image.base();
        let vftables = [(0x4f8usize, 0x440usize), (0x518, 0x460)];
        for (slot, col) in vftables {
            let value = base + col as u64;
            image.bytes[slot..slot + 8].copy_from_slice(&value.to_le_bytes());
        }
        // The object: vfptr (D/B/A) at 0, vfptr (C) at 16.
        let mut object = [0u64; 4];
        object[0] = base + 0x500;
        object[2] = base + 0x520;
        let complete = object.as_ptr() as u64;
        let td = |at: u64| base + at;
        let cast = |from: u64, source: u64, target: u64| {
            winrun_rt_dynamic_cast_with_context(from, 0, td(source), td(target), 0, std::ptr::null_mut())
        };
        assert_eq!(cast(complete, 0x180, 0x100), complete, "A* -> D* downcast");
        assert_eq!(cast(complete, 0x180, 0x140), complete, "A* -> B* downcast");
        assert_eq!(cast(complete, 0x180, 0x1c0), complete + 16, "A* -> C* cross-cast");
        assert_eq!(cast(complete + 16, 0x1c0, 0x180), complete, "C* -> A* cross-cast");
        assert_eq!(cast(complete, 0x180, 0x200), 0, "unrelated type");
        assert_eq!(native_rt_cast_to_void(complete + 16), complete);
        assert_eq!(cast(0, 0x180, 0x100), 0, "null stays null");
    }
}
