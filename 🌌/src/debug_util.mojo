from memory.anypointer import AnyPointer
from memory import memcpy
from buffer import Buffer

fn addr_to_int_slow[T: Movable](addr: AnyPointer[T]) -> Int64:
    "Parse string to int."
    var s = str(addr)
    try:
        return atol(s)
    except ValueError:
        return 0
    
fn read64(addr: Pointer[Int64]) -> Int64:
    var val: Int64 = -1

    var val_addr = AnyPointer.address_of(val)
    var val_addr_p = Pointer(val_addr.value)

    memcpy(val_addr_p, addr, 1)
    return val

fn read64_any[T: AnyType](addr: Pointer[T]) -> Int64:
    return read64(addr.bitcast[Int64]())

fn read64_as_ptr(addr: Pointer[Int64]) -> Pointer[Int64]:
    var out = Pointer[Int64]()
    var out_ptr = ref_to_int_ptr(Reference(out))
    memcpy(out_ptr, addr, 1)
    return out

fn int_to_ptr(i: Int64) -> Pointer[Int64]:
    var new_ptr = Pointer[Int64]()
    var new_ptr_addr = ref_to_int_ptr(Reference(new_ptr))
    write64[Int64](new_ptr_addr, i)
    return new_ptr

fn ptr_to_int(ptr: Pointer) -> Int64:
    var ptr_ = ptr.bitcast[Int64]()
    var ptr_addr = ref_to_int_ptr(Reference(ptr_))
    return read64(ptr_addr)

fn int_to_ptr_any[T: AnyType](i: Int64) -> Pointer[T]:
    var p = int_to_ptr(i)
    return p.bitcast[T]()

fn write64[T: AnyType](addr: Pointer[T], val_in: Int64):
    var val: Int64 = val_in

    var addr_p = addr.bitcast[Int64]()

    var val_addr = AnyPointer.address_of(val)
    var val_addr_p = Pointer(val_addr.value)

    memcpy(addr_p, val_addr_p, 1)

fn ref_to_int_ptr(val: Reference) -> Pointer[Int64]:
    var addr = val.get_unsafe_pointer()
    var addr_p = addr.bitcast[Int64]()
    return addr_p

fn ptr_to_int_ptr[T: AnyType](val: Pointer[T]) -> Pointer[Int64]:
    var ptr = val.bitcast[Int64]()
    return ptr


trait DebugPrint(AnyType):
    @staticmethod
    fn debug_print_ptr(ptr: Pointer[Int64]):
        pass


'''
fn sizeof[T: AnyType]() -> Int64:
    var p = Pointer[T]()
    var p2 = p + 1
    return ptr_to_int(p2) - ptr_to_int(p)
'''

from sys.info import sizeof
from utils.variant import Variant

fn debug_print(ref: Reference[StringLiteral]):
    var ptr = ref_to_int_ptr(ref)
    print('== DEBUG StringLiteral @',ptr,' ==')
    var data_ptr = read64_as_ptr(ptr)
    print('Data Pointer: ', data_ptr)
    var length = read64(ptr + 1)
    print('Length: ', length)

from collections.dict import _DictIndex

fn debug_print[K: KeyElement, V: CollectionElement](ref: Reference[Dict[K,V]]):
    var ptr = ref_to_int_ptr(ref)
    print('== DEBUG Dict[K,V] @',ptr,' ==')
    var num_els = read64(ptr)
    print('Num Elements: ', num_els)
    print('Allocated: ', read64(ptr + 1))
    print('Capacity: ', read64(ptr + 2))
    var dict_index = read64_as_ptr(ptr + 3)
    var dict_index_ = dict_index.bitcast[_DictIndex]()

    print('Dict Index: ', dict_index)
    var entries_list = read64_as_ptr(ptr + 4)
    print('Entries List: ', entries_list)





fn debug_print[T: CollectionElement](ref: Reference[List[T]]):
    var ptr = ref_to_int_ptr(ref)
    return debug_print_ptr[T](ptr)

fn debug_print_ptr[T: CollectionElement](ptr: Pointer[Int64]):
    print('== DEBUG List[T] @',ptr,' ==')
    var data_ptr = read64_as_ptr(ptr)
    print('Data Pointer: ', data_ptr)
    var length = read64(ptr + 1)
    print('Length: ', length)
    var chunk_size = sizeof[T]()
    print('Element Size: ', chunk_size)

    if length > 10:
        length = 10

    var data_ptr_t = data_ptr.bitcast[T]()
    for i in range(length):
        var next_ptr = data_ptr_t + i
        print(
            'Element [',i,'] @',
            next_ptr,'->',
            hex(read64(next_ptr.bitcast[Int64]()))
        )


fn debug_print[T: DebugPrint](ref: Reference[T]):
    var ptr = ref_to_int_ptr(ref)
    T.debug_print_ptr(ptr)
    

fn debug_dump[T: AnyType](ref: Reference[T]):
    var ptr = ref_to_int_ptr(ref)
    print('== DEBUG [',ptr,'] ==')

    for i in range(8):
        var addr = ptr + i
        var val2 = read64(addr)
        print('[',hex(i*8),']', hex(val2))