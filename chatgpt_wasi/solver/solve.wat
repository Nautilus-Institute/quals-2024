(module
  (type (;0;) (func (param i64 i64)))
  (type (;1;) (func (param i64)))
  (type (;2;) (func))
  (import "env" "check_variable" (func (;0;) (type 0)))
  (import "env" "print_number" (func (;1;) (type 1)))
  (func (;2;) (type 2)
    global.get 67
    call 1
    i64.const 0x01007f4b
    global.set 67
    call 0
  )
  (memory (;0;) 16)
  (global (;0;) (mut i32) (i32.const 1048576))
  (export "memory" (memory 0))
  (export "_start" (func 2)))
