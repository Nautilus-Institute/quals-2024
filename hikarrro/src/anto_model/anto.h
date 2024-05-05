// Bundle API auto-generated header file. Do not edit!
// Glow Tools version: 2022-07-21 (58ce44b15) ()

#ifndef _GLOW_BUNDLE_ANTO_H
#define _GLOW_BUNDLE_ANTO_H

#include <stdint.h>

// ---------------------------------------------------------------
//                       Common definitions
// ---------------------------------------------------------------
#ifndef _GLOW_BUNDLE_COMMON_DEFS
#define _GLOW_BUNDLE_COMMON_DEFS

// Glow bundle error code for correct execution.
#define GLOW_SUCCESS 0

// Memory alignment definition with given alignment size
// for static allocation of memory.
#define GLOW_MEM_ALIGN(size)  __attribute__((aligned(size)))

// Macro function to get the absolute address of a
// placeholder using the base address of the mutable
// weight buffer and placeholder offset definition.
#define GLOW_GET_ADDR(mutableBaseAddr, placeholderOff)  (((uint8_t*)(mutableBaseAddr)) + placeholderOff)

#endif

// ---------------------------------------------------------------
//                          Bundle API
// ---------------------------------------------------------------
// Model name: "anto"
// Total data size: 1583424 (bytes)
// Activations allocation efficiency: 1.0000
// Placeholders:
//
//   Name: "serving_default_input_1_0"
//   Type: float<1 x 256>
//   Size: 256 (elements)
//   Size: 1024 (bytes)
//   Offset: 0 (bytes)
//
//   Name: "StatefulPartitionedCall_0"
//   Type: float<1 x 64>
//   Size: 64 (elements)
//   Size: 256 (bytes)
//   Offset: 1024 (bytes)
//
//   Name: "StatefulPartitionedCall_1"
//   Type: float<1 x 64>
//   Size: 64 (elements)
//   Size: 256 (bytes)
//   Offset: 1280 (bytes)
//
// NOTE: Placeholders are allocated within the "mutableWeight"
// buffer and are identified using an offset relative to base.
// ---------------------------------------------------------------
#ifdef __cplusplus
extern "C" {
#endif

// Placeholder address offsets within mutable buffer (bytes).
#define ANTO_input_1  0
#define ANTO_output_0  1024
#define ANTO_output_1  1280

// Memory sizes (bytes).
#define ANTO_CONSTANT_MEM_SIZE     1577536
#define ANTO_MUTABLE_MEM_SIZE      1536
#define ANTO_ACTIVATIONS_MEM_SIZE  4352

// Memory alignment (bytes).
#define ANTO_MEM_ALIGN  64

// Bundle entry point (inference function). Returns 0
// for correct execution or some error code otherwise.
int anto(uint8_t *constantWeight, uint8_t *mutableWeight, uint8_t *activations);

#ifdef __cplusplus
}
#endif
#endif
