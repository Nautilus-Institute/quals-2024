import Foundation;

// constants we will use for part1
let part1_protected_pins : [UInt32] = [0];

enum VMError: Error {
	case decodeError(msg: String)
	case todo
	case notImplemented
	case reservedOrUndefined
	case invalidDest(msg: String)
	case validationError
	case untrusted
}

enum InsnRet : UInt32 {
	case success;
	case skipPCUpdate;
}

class FIFO {
	// a single FIFO inside a PIO block

	enum FIFOError : Error {
		case emptyFIFO
	};

	// first element is newest, last element is oldest
	var queue : [UInt32] = [];
	var depth : Int;

	// for simplicity we assume that we are always 32b wide
	// depth is configurable
	init(depth: Int) {
		self.depth = depth
	}

	@discardableResult func push(val: UInt32) -> Bool {
		if (self.count() >= depth) {
			// we are full
			return false
		}
		self.queue.append(val)
		return true
	}

	func pull() -> Result<UInt32, FIFO.FIFOError> {
		if (self.count() == 0) {
			// we are empty
			return Result.failure(FIFOError.emptyFIFO)
		}
		return Result.success(self.queue.removeLast())
	}

	// helper methods
	func count() -> Int {
		return self.queue.count
	}

	func full() -> Bool {
		self.count() == self.depth
	}

	func empty() -> Bool {
		self.count() == 0
	}

	func set_depth(depth: Int) throws {
		if !self.empty() {
			throw VMError.reservedOrUndefined
		}
		self.depth = depth
	}
}

class Instruction {
	// Representation of a single PIO instruction

	var name: String;
	var sideset: UInt16;

	// ------------------------------------------------------------
	// below are variables that will be modifying during execution

	// the delay we are currently experiencing while executing this instruction
	var curr_delay = 0;
	init(name: String, sideset: UInt16) {
		self.name = name;
		self.sideset = sideset
	}

	func execute(sm: StateMachine, pio: PIO) throws -> InsnRet {
		// must be overriden by children
		throw VMError.notImplemented;
	}

	func validate(sm: StateMachine, pio: PIO) throws {
		// must be overriden by children
		throw VMError.notImplemented
	}

	func handle_sideset(sm: StateMachine, pio: PIO) throws {
		// this function actually handles both sidesets, and delays
		if (sm.sideset_count > 0) {

			var do_sideset = false;

			// if no enable bit, every instruction will perform side-set
			if (sm.side_en == false) {
				// enable bit is not set and we have a sideset count
				do_sideset = true
			} else {
				// enable bit is set, check ours
				if ((self.sideset >> 4) == 1) {
					do_sideset = true
				}
			}
 
			if (do_sideset) {
				// we don't validate this here because you can only set pins, not read them
				var count : UInt32 = 0;
				if (sm.sideset_count > 0) {
					count = (sm.sideset_count) + (sm.side_en ? 1 : 0);
				}
				// mask off enable bit, if we are using it
				var value = UInt32(self.sideset) & (sm.side_en ? 0xf : 0x1f)
				value >>= (5 - count);

				var mask : UInt32 = (1 << (sm.sideset_count - (sm.side_en ? 1 : 0))) - 1;
				mask <<= sm.side_base;

				// we are instructed to do our sidesetting here. make sure we handle wrap
				if sm.side_base + sm.sideset_count > 31 {
					// mask and set the top part
					let top_mask: UInt32 = 0x1f << min(sm.side_base, 31);
					let bottom_bitcount = sm.side_base + sm.sideset_count - 32;
					let bottom_mask: UInt32 = (1 << (bottom_bitcount)) - 1;
					if (sm.side_pindirs) {
						pio.gpio_pindirs = (pio.gpio_pindirs & (~top_mask)) | (value << sm.side_base);
						pio.gpio_pindirs &= 0xffffffff;
						pio.gpio_pins = (pio.gpio_pindirs & (~bottom_mask)) | (value >> (bottom_bitcount));
					} else {
						pio.gpio_pins = (pio.gpio_pins & (~top_mask)) | (value << sm.side_base);
						pio.gpio_pins &= 0xffffffff;
						pio.gpio_pins = (pio.gpio_pins & (~bottom_mask)) | (value >> (bottom_bitcount));					
					}
				} else {
					// simple - mask, set, update
#if DEBUG
					print("mask: \(mask) sidebase \(sm.side_base) count: \(sm.sideset_count) value: \(value) pins: \(pio.gpio_pins) pindirs: \(pio.gpio_pindirs)")
#endif
					if (sm.side_pindirs) {
						pio.gpio_pindirs = (pio.gpio_pindirs & (~mask)) | (value << sm.side_base);
					} else {
#if DEBUG
						print("masked: \(pio.gpio_pins & (~mask)) shifted: \(value << sm.side_base)")
#endif
						pio.gpio_pins = (pio.gpio_pins & (~mask)) | (value << sm.side_base);
#if DEBUG
						print("pins after: \(pio.gpio_pins)")
#endif
					}
				}
			}
		}

		if (self.sideset > 0) {
			// calculate our delay, if any. we mask off the real sideset bits
			var count : UInt32 = 0;
			if (sm.sideset_count > 0) {
				count = (sm.sideset_count) + (sm.side_en ? 1 : 0);
			}
			let mask : UInt32 = (1 << (5 - count)) - 1
			// mask off enable bit, if we are using it
			let delay = UInt32(self.sideset) & mask

			if (delay > 0) {
				sm.curr_delay = Int(delay);
			}
		}
	}

	// func desc() -> String {
	// 	return "Instruction<\(self.name)>";
	// }
}

class JmpInstruction: Instruction {

	var addr : UInt32 = 0;
	var cond : UInt32 = 0;

	init(raw : UInt16, sideset: UInt16) {
		super.init(name: "Jmp", sideset: sideset);
		self.addr = UInt32(raw & 0x1f);
		self.cond = UInt32((raw >> 5) & 0x7);
	}

	override func execute(sm: StateMachine, pio: PIO) throws -> InsnRet {
		var cond = false;
		switch self.cond {
			case 0:
				// always true
				cond = true
			case 1:
				// !X
				cond = sm.scratch_x == 0
			case 2:
				// if (X--)
				cond = sm.scratch_x > 0;
				sm.scratch_x &-= 1;
			case 3:
				// !Y
				cond = sm.scratch_y == 0
			case 4:
				// if (Y--)
				cond = sm.scratch_y > 0;
				sm.scratch_y &-= 1;
			case 5:
				// X!=Y
				cond = sm.scratch_x != sm.scratch_y
			case 6:
				// branch on input pin
				cond = (pio.gpio_pins >> sm.jmp_pin) & 1 == 1
			case 7:
				// output_shift_register not empty (!OSRE)
				cond = !(sm.output_shift_counter >= sm.pull_thresh)
			default:
				throw VMError.notImplemented
		}

		if cond {
			sm.pc = self.addr;
			return InsnRet.skipPCUpdate;
		}

		return InsnRet.success;
	}

	override func validate(sm: StateMachine, pio: PIO) throws {
		if self.cond == 6 {
			if part1_protected_pins.contains(sm.jmp_pin) {
				throw VMError.validationError
			}
		}
	}
}

class WaitInstruction: Instruction {

	var index: UInt32 = 0;
	var source: UInt32 = 0;
	var pol: UInt32 = 0;

	init(raw : UInt16, sideset: UInt16) {
		super.init(name: "Wait", sideset: sideset);
		self.index = UInt32(raw & 0x1f);
		self.source = UInt32((raw >> 5) & 0x3);
		self.pol = UInt32((raw >> 7) & 1);
	}

	override func execute(sm: StateMachine, pio: PIO) throws -> InsnRet {
		var keepwait = false
		switch self.source {
			case 0:
				// GPIO. this uses an absolute index, not based on in_base
				keepwait = ((pio.gpio_pins >> self.index) & 1) != self.pol
			case 1:
				// PIN
				let idx = (self.index + sm.in_base) & 0x1f;
				keepwait = ((pio.gpio_pins >> idx) & 1) != self.pol
			case 2:
				// IRQ

				// calculate our index (same as WaitInstruction)
				var index = self.index & 0x7;
				if ((self.index >> 4) & 1) != 0 {
					// relative add of sm ID
					index = (sm.id + (self.index & 0x3)) % 4

					// add back remaining bit
					index += (self.index >> 2) & 1
				}
				keepwait = ((pio.irq >> index) & 1) != self.pol

				if (keepwait == false && self.pol == 1) {
					// special case: the datasheet says we should clear the bit
					pio.irq &= ~(1 << index);
				}
			case 3:
				throw VMError.reservedOrUndefined
			default:
				throw VMError.notImplemented
		}

#if DEBUG
		print("wait \(keepwait) val \((pio.gpio_pins >> self.index) & 1) index \(self.index) pol \(self.pol)")
#endif
		if (keepwait) {
			sm.stalled = true;
			return InsnRet.skipPCUpdate
		} else {
			return InsnRet.success
		}
	}

	override func validate(sm: StateMachine, pio: PIO) throws {
		let chk = (sm.in_base + self.index) % 32;
		if part1_protected_pins.contains(chk) {
			throw VMError.validationError;
		}
	}
}

class InInstruction: Instruction {

	var source: UInt32 = 0;
	var bitcount: UInt32 = 0;

	init(raw : UInt16, sideset: UInt16) {
		super.init(name: "In", sideset: sideset);
		self.source = UInt32((raw >> 5) & 0x7);
		self.bitcount = UInt32(raw & 0x1f);
		if self.bitcount == 0 {
			self.bitcount = 32
		}
	}

	override func execute(sm: StateMachine, pio: PIO) throws -> InsnRet {
		var sourceval : UInt32 = 0;

		if sm.stalled == false {

			let mask = (UInt64(1) << UInt64(self.bitcount)) - 1

			switch self.source {
				case 0:
					// PINS
					// handle wrap by just converting to a UInt64
					let x = UInt64(pio.gpio_pins) + (UInt64(pio.gpio_pins) << 32);

					// mask and update
					sourceval = UInt32((x >> sm.in_base) & mask)
#if DEBUG
					print("sm \(sm.id) ininst-value: mask \(mask) inbase \(sm.in_base) sourceval \(sourceval) / fullpins \(pio.gpio_pins)")
#endif
				case 1:
					// X
					sourceval = sm.scratch_x & UInt32(mask & 0xffffffff)
				case 2:
					// Y
					sourceval = sm.scratch_y & UInt32(mask & 0xffffffff)
				case 3:
					// NULL
					sourceval = 0
				case 4:
					// reserved
					throw VMError.reservedOrUndefined
				case 5:
					// reserved
					throw VMError.reservedOrUndefined
				case 6:
					// ISR
					sourceval = sm.input_shift_register & UInt32(mask & 0xffffffff)
				case 7:
					// OSR
					sourceval = sm.output_shift_register & UInt32(mask & 0xffffffff)
				default:
					throw VMError.reservedOrUndefined
			}

			if sm.in_shiftdir {
				// data enters from the left
				sm.input_shift_register >>= self.bitcount
				sm.input_shift_register |= (sourceval << (32 - self.bitcount))
			} else {
				// data enters from the right.
				// "The bit order of the input data is not dependent on the shift direction."
				sm.input_shift_register <<= self.bitcount
				sm.input_shift_register |= sourceval
			}

			sm.input_shift_counter = min(sm.input_shift_counter + self.bitcount, 32)
		}

		if sm.autopush {
			// check if we have matched or exceeded our threshold
			// note that if we exceed, we lose data, and this is expected
			if sm.input_shift_counter >= sm.push_thresh {
				// check if we are able to push to the RX FIFO, or if we should stall
				let pushval = sm.adjusted_isr(cnt: sm.push_thresh);

				// try to push. this will return false if the fifo is full
				if !sm.rx_fifo.push(val: pushval) {
					// we should stall because the rx fifo is full
					// pushval will be the same between throws, the ISR won't be impacted
					sm.stalled = true;
					return InsnRet.skipPCUpdate
				}

				// autopush has completed successfully
#if DEBUG
				print("sm \(sm.id) autopush-value: \(pushval)")
#endif
				sm.input_shift_register = 0
				sm.input_shift_counter = 0;
			}
		}

		return InsnRet.success
	}

	override func validate(sm: StateMachine, pio: PIO) throws {
		// starting from the in_base, check up through the bitcount to see if any pins are protected. if so, disallow it.
		if self.source == 0 {
			for i : UInt32 in (sm.in_base)..<(sm.in_base + self.bitcount) {
				let chk = i < 32 ? i : (i - 32);
				if part1_protected_pins.contains(chk) {
					throw VMError.validationError;
				}
			}
		}
	}
}

class OutInstruction: Instruction {

	var destination: UInt32 = 0;
	var bitcount: UInt32 = 0;

	init(raw : UInt16, sideset: UInt16) {
		super.init(name: "Out", sideset: sideset);
		self.destination = UInt32((raw >> 5) & 0x7);
		self.bitcount = UInt32(raw & 0x1f);
		if self.bitcount == 0 {
			self.bitcount = 32
		}
	}

	override func execute(sm: StateMachine, pio: PIO) throws -> InsnRet {

		// upfront check on autopull, with stalling included
		if sm.autopull {
			if sm.output_shift_counter >= sm.pull_thresh {
				switch sm.tx_fifo.pull() {
					case .failure:
						// if we can't pull, stall
						sm.stalled = true;
						return InsnRet.skipPCUpdate
					case .success(let val):
						// copy to OSR
						sm.output_shift_register = val
						sm.output_shift_counter = 0
#if DEBUG
						print("sm \(sm.id) autopull-value: \(val)")
#endif
				}
			}
		}

		// construct our OSR value
		var value : UInt32 = sm.output_shift_register;
		if sm.out_shiftdir {
			// shift bits out to right
			value &= UInt32((UInt64(1) << self.bitcount) - 1);
			sm.output_shift_register >>= self.bitcount;
		} else {
			// shift bits out to left
			value = UInt32(((UInt64(value) << self.bitcount) >> 32) & 0xffffffff);
			sm.output_shift_register = UInt32((UInt64(sm.output_shift_register) << self.bitcount) & 0xffffffff);
		}
#if DEBUG
		print("out-value: \(value) bitcount: \(self.bitcount)");
#endif
		switch self.destination {
			case 0:
				// PINS
				// handle wrap
				if sm.out_base + self.bitcount > 31 {
					// mask and set the top part
					let top_mask: UInt32 = 0x1f << min(sm.out_base, 31);
					pio.gpio_pins = (pio.gpio_pins & (~top_mask)) | (value << sm.out_base);
					pio.gpio_pins &= 0xffffffff;

					// mask and set the bottom part
					let bottom_bitcount = sm.out_base + self.bitcount - 32
					let bottom_mask: UInt32 = (1 << bottom_bitcount) - 1;
					pio.gpio_pins = (pio.gpio_pins & (~bottom_mask)) | (value >> (self.bitcount - bottom_bitcount));
				} else {
					// simple - mask, set, update
					let mask: UInt32 = 0x1f << sm.out_base;
					pio.gpio_pins = (pio.gpio_pins & (~mask)) | (value << sm.out_base);
				}
			case 1:
				// X
				sm.scratch_x = value
			case 2:
				// Y
				sm.scratch_y = value
			case 3:
				// NULL (explicitly disregard the data)
				break;
			case 4:
				// PINDIRS
				// handle wrap
				if sm.out_base + self.bitcount > 31 {
					// mask and set the top part
					let top_mask: UInt32 = 0x1f << min(sm.out_base, 31);
					pio.gpio_pindirs = (pio.gpio_pindirs & (~top_mask)) | (value << sm.out_base);
					pio.gpio_pindirs &= 0xffffffff;

					// mask and set the bottom part
					let bottom_bitcount = sm.out_base + self.bitcount - 32
					let bottom_mask: UInt32 = (1 << bottom_bitcount) - 1;
					pio.gpio_pindirs = (pio.gpio_pindirs & (~bottom_mask)) | (value >> (self.bitcount - bottom_bitcount));
				} else {
					// simple - mask, set, update
					let mask: UInt32 = 0x1f << sm.out_base;
					pio.gpio_pindirs = (pio.gpio_pindirs & (~mask)) | (value << sm.out_base);
				}
			case 5:
				// PC
				sm.pc = value;
			case 6:
				// ISR
				sm.input_shift_register = value
				sm.input_shift_counter = self.bitcount
			default:
				throw VMError.invalidDest(msg: "bad dest \(self.destination)");
		}

		sm.output_shift_counter = min(sm.output_shift_counter + self.bitcount, 32)

		if sm.autopull {
			if sm.output_shift_counter >= sm.pull_thresh {
				switch sm.tx_fifo.pull() {
					case .failure:
						// if we can't pull, do nothing here
						break;
					case .success(let val):
						// copy to OSR
						sm.output_shift_register = val
						sm.output_shift_counter = 0
#if DEBUG
						print("sm \(sm.id) autopull-value: \(val)")
#endif
				}
			}
		}

		return InsnRet.success;
	}

	override func validate(sm: StateMachine, pio: PIO) throws {
		// starting from the out_base, check up through the bitcoin to see if any pins are protected. if so, disallow it.
		if self.destination == 0 {
			for i : UInt32 in (sm.out_base)..<(sm.out_base + self.bitcount) {
				let chk = i < 32 ? i : (i - 32);
				if part1_protected_pins.contains(chk) {
					throw VMError.validationError;
				}
			}
		}
	}
}

class PullInstruction: Instruction {

	var if_empty : UInt16 = 0;
	var block : UInt16 = 0;

	init(raw : UInt16, sideset: UInt16) {
		super.init(name: "Pull", sideset: sideset);
		self.if_empty = (raw >> 6) & 1;
		self.block = (raw >> 5) & 1;
	}

	override func execute(sm: StateMachine, pio: PIO) throws -> InsnRet {
		if sm.autopull {
			if sm.output_shift_counter >= sm.pull_thresh {
				// datasheet says this is a no-op
				return InsnRet.success
			}
		}

		if self.if_empty == 1 {
			if sm.output_shift_counter < sm.pull_thresh {
				// "do nothing unless the total output shift count has reached its threshold"
				if self.block != 0 {
					sm.stalled = true;
					return InsnRet.skipPCUpdate
				} else {
					return InsnRet.success
				}
			}
		}

		switch sm.tx_fifo.pull() {
			case .failure:
				// we stall here
				if self.block != 0 {
					sm.stalled = true;
					return InsnRet.skipPCUpdate
				} else {
					// pull from X
					sm.output_shift_register = sm.scratch_x
				}
			case .success(let val):
				// copy to OSR
				sm.output_shift_register = val
		}

		sm.output_shift_counter = 0
		return InsnRet.success
	}

	override func validate(sm: StateMachine, pio: PIO) throws {
		// this function doesn't use gpio bits directly so we have nothing to validate
	}
}

class PushInstruction: Instruction {

	var if_full : UInt16 = 0;
	var block : UInt16 = 0;

	init(raw : UInt16, sideset: UInt16) {
		super.init(name: "Push", sideset: sideset);
		self.if_full = (raw >> 6) & 1;
		self.block = (raw >> 5) & 1;
	}

	override func execute(sm: StateMachine, pio: PIO) throws -> InsnRet {
		if self.if_full != 0 {
			// check pull_thresh
			if sm.push_thresh != sm.input_shift_counter {
				return InsnRet.skipPCUpdate
			}
		}

		if sm.rx_fifo.full() {
			if self.block != 0 {
				return InsnRet.skipPCUpdate
			} else {
				// full but no block - this merely clears ISR and continues
				// this intentionally does nothing
				// real hardware sets FDEBUG_RXSTALL
			}
		} else {
			// we are not full. push ISR and clear it
			switch sm.rx_fifo.push(val: sm.input_shift_register) {
				case true:
					// expected (only?) case
					break
				case false:
					// totally unexpected
					throw VMError.reservedOrUndefined
			}
		}
		sm.input_shift_register = 0
		sm.input_shift_counter = 0

		return InsnRet.success
	}

	override func validate(sm: StateMachine, pio: PIO) throws {
		// this function doesn't use gpio bits directly so we have nothing to validate
	}
}

class MovInstruction: Instruction {

	var destination : UInt16 = 0;
	var op : UInt16 = 0;
	var source: UInt16 = 0;

	init(raw : UInt16, sideset: UInt16) {
		super.init(name: "Mov", sideset: sideset);
		self.destination = (raw >> 5) & 0x7;
		self.op = (raw >> 3) & 0x3;
		self.source = raw & 0x7;
	}

	override func execute(sm: StateMachine, pio: PIO) throws -> InsnRet {

		// first, read the source value
		var sourceval : UInt32 = 0;
		switch self.source {
			case 0:
				// PINS: handle wrap by just converting to a UInt64, then reading 32 bits from in_base

				var pinsrc = pio.gpio_pins;

				// mask off all protected pins
				for p in part1_protected_pins {
					let mask = 0xffffffff - (1 << p);
					pinsrc &= UInt32(mask);
				}

				let x = UInt64(pinsrc) + (UInt64(pinsrc) << 32);
				sourceval = UInt32((x >> sm.in_base) & 0xffffffff);
			case 1:
				// X
				sourceval = sm.scratch_x
			case 2:
				// Y
				sourceval = sm.scratch_y
			case 3:
				// NULL
				sourceval = 0
			case 4:
				// reserved
				throw VMError.reservedOrUndefined
			case 5:
				// STATUS (this is a weird one)
				if sm.status_sel == 1 {
					sourceval = sm.rx_fifo.count() < sm.status_n ? UInt32(0xffffffff) : UInt32(0x0)
				} else {
					sourceval = sm.tx_fifo.count() < sm.status_n ? UInt32(0xffffffff) : UInt32(0x0);
				}
			case 6:
				// ISR
				sourceval = sm.input_shift_register
			case 7:
				// OSR
				// mov [...], OSR is undefined if autopull is enabled because of the async nature of autopull
				sourceval = sm.output_shift_register
			default:
				throw VMError.reservedOrUndefined
		}

		// ok, now apply our operation
		switch self.op {
			case 0:
				 // none
				 break
			 case 1:
			 	// invert (bitwise complement)
			 	sourceval = ~sourceval;
			 case 2:
			 	// bit-reverse
			 	var res : UInt32 = 0;
			 	for _ in 0..<32 {
			 		res = (res << 1) | (sourceval & 1)
			 		sourceval >>= 1;
			 	}
			 	sourceval = res;
		 	case 3:
		 		// reserved
		 		throw VMError.reservedOrUndefined
		 	default:
		 		throw VMError.reservedOrUndefined
		}

		var retval = InsnRet.success

		switch self.destination {
			case 0:
				// PINS
				// mask and set the top part
				let top_mask: UInt32 = UInt32((UInt64(0xffffffff) << min(sm.out_base, 31)) & 0xffffffff);
				pio.gpio_pins = (pio.gpio_pins & (~top_mask)) | (sourceval << sm.out_base);
				pio.gpio_pins &= 0xffffffff;

				// mask and set the bottom part
				let bottom_bitcount = sm.out_base
				let bottom_mask: UInt32 = (1 << bottom_bitcount) - 1;
				pio.gpio_pins = (pio.gpio_pins & (~bottom_mask)) | (sourceval >> (32 - bottom_bitcount));
			case 1:
				// X
				sm.scratch_x = sourceval
			case 2:
				// Y
				sm.scratch_y = sourceval
			case 3:
				// reserved
				throw VMError.reservedOrUndefined
			case 4:
				// EXEC -- we won't support this here
				throw VMError.reservedOrUndefined
			case 5:
				// PC
				sm.pc = sourceval
				retval = InsnRet.skipPCUpdate
			case 6:
				// ISR
				sm.input_shift_register = sourceval
				sm.input_shift_counter = 0 // empty
			case 7:
				// OSR
				sm.output_shift_register = sourceval
				sm.output_shift_counter = 0; // nothing yet shifted out
			default:
				throw VMError.reservedOrUndefined
		}
		
		return retval
	}

	override func validate(sm: StateMachine, pio: PIO) throws {
		// weirdly there is nothing to validate here, because we can safely mask off protected pins for source: PINS
		// if we didn't mask, this instruction could never use that source, since it always reads the full 32b value
	}
}

class IrqInstruction: Instruction {

	var clr : UInt32 = 0;
	var wait : UInt32 = 0;
	var index: UInt32 = 0;

	init(raw : UInt16, sideset: UInt16) {
		super.init(name: "Irq", sideset: sideset);
		self.clr = UInt32((raw >> 6) & 1);
		self.wait = UInt32((raw >> 5) & 1);
		self.index = UInt32(raw & 0x1f);
	}

	override func execute(sm: StateMachine, pio: PIO) throws -> InsnRet {

		// not sure how to handle this bit (bit 3)
		if ((self.index >> 3) & 1) != 0 {
			throw VMError.reservedOrUndefined
		}

		// calculate our index
		var index = self.index & 0x7;
		if ((self.index >> 4) & 1) != 0 {
			// relative add of sm ID
			index = (sm.id + (self.index & 0x3)) % 4

			// add back remaining bit
			index += (self.index & 4)
		}

		// setting clr means we ignore wait, according to datasheet
		if self.clr == 1 {
			// clear IRQ flag
			pio.irq &= (0xff - (1 << index))
		} else if self.wait == 1{
			// just wait until the flag is unset
			if (pio.irq & (1 << index)) > 0 {
				// stall
				sm.stalled = true;
				return InsnRet.skipPCUpdate
			}
		} else {
			// set IRQ flag
			pio.irq |= (1 << index);
		}

		return InsnRet.success
	}

	override func validate(sm: StateMachine, pio: PIO) throws {
		// this function doesn't use gpio bits directly so we have nothing to validate
	}
}

class SetInstruction: Instruction {

	var destination: UInt32 = 0;
	var data: UInt32 = 0;

	init(raw : UInt16, sideset: UInt16) {
		super.init(name: "Set", sideset: sideset);
		self.destination = UInt32((raw >> 5) & 0x7);
		self.data = UInt32(raw & 0x1f);
	}

	override func execute(sm: StateMachine, pio: PIO) throws -> InsnRet {
		switch self.destination {
			case 0:
				// PINS
				// handle wrap
				if sm.set_base + 5 > 31 {
					// mask and set the top part
					let top_mask: UInt32 = 0x1f << min(sm.set_base, 31);
					pio.gpio_pins = (pio.gpio_pins & (~top_mask)) | (self.data << sm.set_base);
					pio.gpio_pins &= 0xffffffff;
					sm.set_base = (sm.set_base + 5) & 0x1f;

					// mask and set the bottom part
					let bottom_mask: UInt32 = 0x1f >> (5 - sm.set_base);
					pio.gpio_pins = (pio.gpio_pins & (~bottom_mask)) | (self.data >> (5 - sm.set_base));
				} else {
					// simple - mask, set, update
					let mask: UInt32 = 0x1f << sm.set_base;
					pio.gpio_pins = (pio.gpio_pins & (~mask)) | (self.data << sm.set_base);
					sm.set_base += 5;
				}
			case 1:
				// X
				sm.scratch_x = self.data
			case 2:
				// Y
				sm.scratch_y = self.data
			case 4:
				// PINDIRS
				// handle wrap
				if sm.set_base + 5 > 31 {
					// mask and set the top part
					let top_mask: UInt32 = 0x1f << min(sm.set_base, 31);
					pio.gpio_pindirs = (pio.gpio_pindirs & (~top_mask)) | (self.data << sm.set_base);
					pio.gpio_pindirs &= 0xffffffff;
					sm.set_base = (sm.set_base + 5) & 0x1f;

					// mask and set the bottom part
					let bottom_mask: UInt32 = 0x1f >> (5 - sm.set_base);
					pio.gpio_pindirs = (pio.gpio_pindirs & (~bottom_mask)) | (self.data >> (5 - sm.set_base));
				} else {
					// simple - mask, set, update
					let mask: UInt32 = 0x1f << sm.set_base;
					pio.gpio_pindirs = (pio.gpio_pindirs & (~mask)) | (self.data << sm.set_base);
					sm.set_base += 5;
				}
			default:
				throw VMError.invalidDest(msg: "bad dest \(self.destination)");
		}
		return InsnRet.success;
	}

	override func validate(sm: StateMachine, pio: PIO) throws {
		if [0, 4].contains(self.destination) {
			for i : UInt32 in (sm.set_base)..<(sm.set_base + 5) {
				let chk = i < 32 ? i : (i - 32);
				if part1_protected_pins.contains(chk) {
					throw VMError.validationError;
				}
			}			
		}
	}
}

class StateMachine {
	// a single state machine inside a PIO block

	// meta variable. if this is not set, the SM won't tick
	var initialized : Bool = false;

	var id: UInt32;

	// we purposely make these plain integers to make reversing a little easier
	var output_shift_register : UInt32 = 0;
	var input_shift_register : UInt32 = 0;

	var output_shift_counter : UInt32 = 32; // 32 == nothing left to be shifted out
	var input_shift_counter : UInt32 = 0; // 0 = nothing shifted in

	var scratch_x : UInt32 = 0;
	var scratch_y : UInt32 = 0;

	var pc : UInt32 = 0;

	// our current delay to process, prior to the next instruction
	var curr_delay : Int = 0;

	// pin selected for jmp
	var jmp_pin: UInt32 = 0;

	// 0 => shift output to left
	// 1 => shift output to right
	var in_shiftdir: Bool = true;
	var out_shiftdir : Bool = true;
	var pull_thresh : UInt32 = 0;
	var push_thresh : UInt32 = 0;
	var autopull : Bool = false;
	var autopush : Bool = false;

	// we set this if we are stalled and re-entering an instruction
	// some instructions take partial effect before stalling, so we
	// want to be sure we don't accidentally execute the prior-to-stall
	// portions more than once. when do we stall? see 3.2.4 in datasheet
	var stalled : Bool = false;

	// number of bits to use for side-set, vs delay
	var sideset_count: UInt32 = 0;

	// whether the MSB of delay/ss is an enable bit
	var side_en: Bool = false;

	// whether the ss impacts pindirs (true) or pins (false)
	var side_pindirs : Bool = false;

	// pin # base for various instructions and ss
	var in_base : UInt32 = 0;
	var out_base : UInt32 = 0;
	var set_base : UInt32 = 0;
	var side_base : UInt32 = 0;

	// pc value at which we wrap to wrap_bottom
	var wrap_top: UInt32 = 0x1f;
	var wrap_bottom: UInt32 = 0;

	// our two fifos. we have one in each direction
	var tx_fifo: FIFO;
	var rx_fifo: FIFO;

	// status_sel and status_n, used for 'MOV STATUS'.
	var status_sel : UInt32 = 0;
	var status_n : UInt32 = 0;

	var pio : PIO;

	// validated SM is allowed to run at all
	var validated : Bool;

	// trusted SM is allowed to execute protected instructions
	var trusted : Bool = false;

	init(id: UInt32, pio: PIO) {
		// the broader PIO, which we'll need for mutating state
		self.pio = pio;

		self.id = id

		self.validated = false;

		// by default we make each fifo 4 deep
		self.tx_fifo = FIFO(depth: 4)
		self.rx_fifo = FIFO(depth: 4)
	}

	func tick() throws {

		// check if we have an active delay. if so, process it
		// note that delays occur after we complete a stalled instruction,
		// whereas sidesets do not wait
		if (self.stalled == false) {
			if (self.curr_delay > 0) {
				self.curr_delay -= 1;
#if DEBUG
				print("sm \(self.id) next instruction delay cycle, \(self.curr_delay) remaining. next pc \(self.pc)")
#endif
				return;
			}
		}

		// if we are untrusted, make sure we do not execute protected instructions
		if !self.trusted && (self.pc < pio.protected_insn_top) {
			throw VMError.untrusted;
		}

		// grab the next instruction
		let insn = self.pio.instruction_memory[Int(self.pc)];

#if DEBUG
		print("sm \(self.id) next instruction: pc \(self.pc)");
		dump(insn);
#endif

		// used to track whether we have, within the lifecycle of a single
		// instruction, applied the side-set/delay already.
		let ssdelay_applied = self.stalled;

		// we always unstall here. the instruction must stall us again if it decides to
		self.stalled = false;

		// run the instruction against the current state machine, and our associated PIO
		switch try insn.execute(sm: self, pio: self.pio) {
			case InsnRet.success:
				// successful instruction, so increment pc and continue
				if self.pc == self.wrap_top {
					self.pc = self.wrap_bottom
				} else {
					self.pc += 1
				}
			case InsnRet.skipPCUpdate:
				// jmp, wait, etc. no need to update pc
				break
		}

		// handle exogenous autopush
		if self.autopull {
			if self.output_shift_counter >= self.pull_thresh {
				switch self.tx_fifo.pull() {
					case .failure:
						// if we can't pull, do nothing
						break;
					case .success(let val):
						// copy to OSR
						self.output_shift_register = val
						self.output_shift_counter = 0
#if DEBUG
						print("sm \(self.id) autopull-value: \(val)")
#endif
				}
			}
		}

		// "If an instruction stalls, the side-set still takes effect immediately."
		// ... but we only want to apply it upfront, once. we don't apply it again,
		// if, say, we are waiting for a long time for a tx fifo to get filled
		if (ssdelay_applied == false) {
			try insn.handle_sideset(sm: self, pio: self.pio)
		}
	}

	func set_fjoin(tx: Bool, rx: Bool) throws {
		// only one at once
		if tx && rx {
			throw VMError.reservedOrUndefined
		}

		if tx {
			self.tx_fifo = FIFO(depth: 8);
			self.rx_fifo = FIFO(depth: 0);
		} else if rx {
			self.rx_fifo = FIFO(depth: 8);
			self.tx_fifo = FIFO(depth: 0);
		} else {
			self.tx_fifo = FIFO(depth: 4)
			self.rx_fifo = FIFO(depth: 4)
		}
	}

	// TODO: are the semantics here correct?
	func adjusted_isr(cnt: UInt32) -> UInt32 {
		// mask and shift the ISR so we return the bits we shifted into it starting from 0
		// we use push_thresh here instead of input_shift_counter because that is the expected
		// behavior, see page 337 of datasheet
		var pushval = UInt32(0);
		if self.in_shiftdir {
			// use the top bits, up to push_thresh
			pushval = (self.input_shift_register >> (32 - cnt));
		} else {
			// use the bottom bits, up to push_thresh
			pushval = (self.input_shift_register & ((1 << cnt) - 1));
		}
		return pushval
	}

	func validate() throws {
		// do validation
		if self.validated || self.trusted {
			return;
		}

		// go through each instruction, protected range excluded
		for insn in self.pio.instruction_memory[Int(self.wrap_bottom)...Int(self.wrap_top)] {
			try insn.validate(sm: self, pio: self.pio);
		}

		// sanity check some fields
		if self.sideset_count + (self.side_en ? 1 : 0) > 5 {
			throw VMError.validationError;
		}

		if self.side_base > 31 {
			throw VMError.validationError;
		}

		if self.in_base > 31 {
			throw VMError.validationError;
		}

		if self.out_base > 31 {
			throw VMError.validationError;
		}

		if self.set_base > 31 {
			throw VMError.validationError;
		}

		if self.wrap_top > 31 {
			throw VMError.validationError;
		}

		if self.pull_thresh > 32 {
			throw VMError.validationError;
		}

		if self.push_thresh > 32 {
			throw VMError.validationError;
		}

		if self.jmp_pin > 31 {
			throw VMError.validationError;
		}

		if self.status_n > 31 {
			throw VMError.validationError;
		}

		// everything has validated
		self.validated = true;
	}
}

class PIO {
	// this class represents a single PIO block. there may be multiple PIO blocks active at once

	var state_machines : [StateMachine] = [];

	var instruction_memory : [Instruction] = [];

	// instructions between 0 and this address, exclusive, are "protected" and can only be run by trusted SMs
	// instructions in a PIO below this range are allowed to access trusted pins
	var protected_insn_top : UInt32 = 0;

	// bitfield representing GPIO pins
	var gpio_pins : UInt32 = 0;

	// bitfield representing GPIO pin directions ("pindirs")
	var gpio_pindirs : UInt32 = 0;

	// 8 IRQ flags shared between all state machines
	var irq : UInt8 = 0;

	// cache whether we are validated or not
	var validated : Bool;

	init() {
		self.validated = false;

		// 4 state machines by default
		for i : UInt32 in 0..<4 {
			self.state_machines.append(StateMachine(id: i, pio: self));
		}
	}

	func tick() throws {
		// for each state machine, run it forward one tick
		// we iterate over count here, not on the array, because the spec says go in order
		for i in 0..<self.state_machines.count {
			let sm = self.state_machines[i];
			if (sm.initialized) {
				try sm.tick();
			}
		}
	}

	func validate() throws {
		if self.validated {
			return;
		}

		for sm in self.state_machines {
			if sm.initialized {
				try sm.validate();
			}
		}
		self.validated = true;
	}
}

class Game {

	var name : String
	var pios: [PIO]

	// number of steps to run the simulation for
	var nsteps = 0;

	init(name: String, pios: [PIO]) {
		self.name = name;
		self.pios = pios;
	}

	func execute() throws {
		// begin emulation of the PIOs. they should run in tandem

		// for each tick, we run each PIO forward one tick
		for _ in 0...self.nsteps {
			for pio in self.pios {
				try pio.tick();
			}
		}
	}

	func validate() throws {
		// validate each PIO
		for pio in self.pios {
			try pio.validate();
		}
	}
}

func decode_instructions(bytes: [UInt8]) throws -> [Instruction] {
	// decode a series of bytes into an instruction bitstream
	// each instruction is 16 bits so every 2 byte is an instruction

	var ret : [Instruction] = [];

	for i in stride(from: 0, to: bytes.count, by: 2) {
		let raw_insn = UInt16(bytes[i]) | (UInt16(bytes[i+1]) << 8);
		let side_set = (raw_insn >> 8) & 0x1f;
#if DEBUG
		print("instruction: \(raw_insn)");
#endif

		let insn = switch (raw_insn >> 13) {
			case 0:
				JmpInstruction(raw: raw_insn, sideset: side_set)
			case 1:
				WaitInstruction(raw: raw_insn, sideset: side_set)
			case 2:
				InInstruction(raw: raw_insn, sideset: side_set)
			case 3:
				OutInstruction(raw: raw_insn, sideset: side_set)
			case 4:
				if (raw_insn >> 7) & 1 != 0 {
					PullInstruction(raw: raw_insn, sideset: side_set)
				} else {
					PushInstruction(raw: raw_insn, sideset: side_set)
				}
			case 5:
				MovInstruction(raw: raw_insn, sideset: side_set)
			case 6:
				IrqInstruction(raw: raw_insn, sideset: side_set)
			case 7:
				SetInstruction(raw: raw_insn, sideset: side_set)
			default:
				throw VMError.decodeError(msg: "invalid opc")
		};
		ret.append(insn);
	}
	return ret;
} 

func receive_input(sm: StateMachine) throws {
	// this function is responsible for receiving player input
	// we want to do this and provide maximum flexibility without making it too obvious what is going on
	let data = readLine()!;
	let userinput = try JSONSerialization.jsonObject(with: data.data(using: String.Encoding.ascii)!, options: .mutableContainers) as? [String:AnyObject]
	for (k, v) in userinput! {
		switch k {
			case "j":
				sm.jmp_pin = v as! UInt32
			case "isd":
				sm.in_shiftdir = v as! Bool
			case "osd":
				sm.out_shiftdir = v as! Bool
			case "pt":
				sm.pull_thresh = v as! UInt32
			case "ps":
				sm.push_thresh = v as! UInt32
			case "at":
				sm.autopull = v as! Bool
			case "as":
				sm.autopush = v as! Bool
			case "sc":
				sm.sideset_count = v as! UInt32
			case "se":
				sm.side_en = v as! Bool
			case "sd":
				sm.side_pindirs = v as! Bool
			case "ib":
				sm.in_base = v as! UInt32
			case "ob":
				sm.out_base = v as! UInt32
			case "seb":
				sm.set_base = v as! UInt32
			case "sb":
				sm.side_base = v as! UInt32
			case "st":
				sm.status_sel = v as! UInt32
			case "sn":
				sm.status_n = v as! UInt32
			case "i":
				let insns = try decode_instructions(bytes: v as! [UInt8])
				let wrap_top = sm.pio.instruction_memory.count + insns.count - 1
				if wrap_top > 31 {
					throw VMError.decodeError(msg: "too long");
				}

				sm.pio.instruction_memory += insns;
				sm.wrap_top = UInt32(wrap_top)
			case "f":
				// let players push data to their input fifo
				for t in (v as! [UInt32]) {
					sm.tx_fifo.push(val: t);
				}
			default:
				break;
		}
	}
}

func setup_game(target: [UInt32]) throws -> [PIO] {
    //         //     .wrap_target
    // 0x9fa0, //  0: pull   block           side 1 [7] 
    // 0xf72f, //  1: set    x, 15           side 0 [7] 
    // 0x7e01, //  2: out    pins, 1         side 1 [6] 
    // 0x1142, //  3: jmp    x--, 2          side 0 [1] 
    //         //     .wrap
	let challenge_tx : [UInt8] = [0xa0, 0x8f, 0x2f, 0xe7, 0x01, 0x6e, 0x42, 0x01];
	let instruction_stream = try decode_instructions(bytes: challenge_tx);
	let tx_wrap = instruction_stream.count - 1

#if DEBUG
	dump(instruction_stream)
#endif

	// create and load our PIO block
	let pio = PIO()
	pio.instruction_memory = instruction_stream

	// uart tx configuration
	do {
		// wrap after our 2 instructions above
		let sm = pio.state_machines[0];
		// wrap after we finish our loaded instructions
		sm.wrap_top = UInt32(tx_wrap);
		sm.wrap_bottom = UInt32(0);

		// set this entire SM's instruction range to be protected
		pio.protected_insn_top = sm.wrap_top + 1;

		// data pin is 0, status pin is 1. set status high at first (stop bit)
		pio.gpio_pins = 2;
		pio.gpio_pindirs = 2;

		// out shift to right
		sm.out_shiftdir = true;

		// pull threshhold
		sm.pull_thresh = 32

		// no autopull
		sm.autopull = false

		// out base is 0 (data pin), sideset base is 1 (active pin)
		sm.out_base = 0;
		sm.side_base = 1;

		// get an deep input fifo
		try sm.set_fjoin(tx: true, rx: false);
		try sm.tx_fifo.set_depth(depth: 0x100);

		// sideset count is 2
		sm.sideset_count = 2

		// opt is set, so use enable bit
		sm.side_en = false;

		// put a word in the tx fifo
		for t in target {
			// we want to send these as 7-stop-1 messages
			// to facilitate that
			sm.tx_fifo.push(val: t);
		}

		sm.initialized = true;

		// tx SM is validated, since it contains no user code
		sm.validated = true;

		// tx SM is trusted and can run protected instructions
		sm.trusted = true;
	}

	do {
		let sm = pio.state_machines[1];

		// start our sm at the rx bytestream
		sm.pc = UInt32(tx_wrap + 1);

		// set wrap after our instructions
		sm.wrap_bottom = sm.pc;

		// receive input and set up the player SM
		try receive_input(sm: pio.state_machines[1])

		// the user did not send us any instructions!
		if sm.wrap_top < sm.wrap_bottom {
			throw VMError.decodeError(msg: "missing");
		}

		try sm.rx_fifo.set_depth(depth: 0x100);

		sm.initialized = true;
	}

	return [pio];
}

// generate a series of random values we want the user to receive
var target : [UInt32] = [];
for _ in 0..<10 {
	target.append(UInt32(Int.random(in: 0..<0xffff)))
}

let pios = try setup_game(target: target);

// ok, execute it
var game = Game(name: "pass-it-on", pios: pios)

game.nsteps = 10000

do {
	try game.validate();
	try game.execute();
} catch {
	print("Unexpected error: \(error)")
}

// compare user rx_fifo to target values

// output the values in the user block rx_fifo
// this is the only output the user will get, and it should give them the flag
for v in 0..<(target.count) {
	switch pios[0].state_machines[1].rx_fifo.pull() {
		case .failure:
			print("bad");
			exit(1);
		case .success(let val):
			if val != target[v] {
				// we did not match
				print("bad \(val) != \(target[v])");
				exit(1);
			}
	}
}

// if we get here, we should give the user the flag
print("res: \(try! String(contentsOf: URL(fileURLWithPath: "/flag")))")
