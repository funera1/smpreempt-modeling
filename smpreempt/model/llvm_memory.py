"""Execute a restricted straight-line summary over explicit live memory objects.

Object identities retain pointer provenance. No PMP/access-control decisions are
made. Out-of-object/unaligned operations are LLVM definedness obligations, not
Host permission checks. This is not an interprocedural LLVM execution engine.
"""
from dataclasses import dataclass, field
import z3

from smpreempt.model.llvm_scalars import Scalar, ScalarSemantics, ByteMemory, UnsupportedLLVM, scalar


@dataclass(frozen=True)
class Pointer:
    object_id: object
    offset: Scalar = field(default_factory=lambda: scalar(0, 64))


@dataclass(frozen=True)
class MemoryObject:
    memory: ByteMemory
    size: int
    alignment: int = 1

    def __post_init__(self):
        if not 0 <= self.size < 1 << 63 or self.alignment < 1 or self.alignment & (self.alignment-1):
            raise ValueError('objects require a finite nonnegative size and power-of-two alignment')


@dataclass(frozen=True)
class MemoryState:
    objects: dict
    ub: object = field(default_factory=lambda: z3.BoolVal(False))


class RelationEvaluator(ScalarSemantics):
    def __init__(self, values, objects, prefix='llvm_relation'):
        super().__init__(values, prefix)
        self.initial = MemoryState(dict(objects))

    @classmethod
    def from_graph(cls, graph, values, objects, prefix='llvm_relation'):
        layout = graph.get('datalayout', '')
        if layout.split('-')[0] != 'e':
            raise UnsupportedLLVM('explicit little-endian datalayout is required')
        # LLVM's default pointer layout is 64-bit. Only address space 0 is
        # supported here; explicit overrides must preserve 64-bit index math.
        for item in layout.split('-'):
            if item.startswith(('p:', 'p0:')):
                parts = item.split(':')
                bits = int(parts[1])
                index = int(parts[4]) if len(parts) > 4 else bits
                if bits != 64 or index != 64:
                    raise UnsupportedLLVM('only 64-bit pointers and 64-bit GEP indices are supported')
        return cls(values, objects, prefix)

    def pointer(self, expression):
        if expression.get('type', {}).get('address_space', 0) != 0:
            raise UnsupportedLLVM('nonzero pointer address space')
        value = self.evaluate(expression)
        if not isinstance(value, Pointer) or value.offset.bits.size() != 64:
            raise UnsupportedLLVM('requires an address-space-0 64-bit object pointer')
        return value

    def access(self, state, pointer, size, alignment):
        if pointer.object_id not in state.objects:
            return z3.BoolVal(False)
        obj = state.objects[pointer.object_id]
        if size is None or size < 1 or alignment is None or alignment < 1:
            raise UnsupportedLLVM('unknown size/alignment')
        if alignment & (alignment-1):
            raise UnsupportedLLVM('non-power-of-two memory alignment')
        if obj.alignment % alignment:
            raise UnsupportedLLVM('object base alignment is insufficient to decide this access')
        offset = pointer.offset.bits
        fits = z3.BoolVal(False) if size > obj.size else z3.ULE(offset, obj.size-size)
        return z3.And(fits, z3.URem(offset, alignment) == 0)

    def evaluate(self, expression):
        kind, op = expression.get('kind'), expression.get('operator')
        if kind == 'reference' and isinstance(self.values.get(expression['id']), Pointer):
            if expression.get('type', {}).get('address_space', 0) != 0:
                raise UnsupportedLLVM('nonzero pointer address space')
            return self.values[expression['id']]
        if op == 'freeze' and expression.get('type', {}).get('llvm') == 'ptr':
            raise UnsupportedLLVM('freezing pointer poison requires a symbolic provenance domain')
        if kind == 'literal' and expression.get('type', {}).get('llvm') == 'ptr' and expression.get('llvm') == 'ptr null':
            return Pointer(None)
        if op == 'getelementptr':
            flags = expression.get('nowrap_flags', int(bool(expression.get('inbounds'))))
            if flags & ~7 or (flags & 6 and not expression.get('inbounds')):
                raise UnsupportedLLVM('standalone nusw/nuw GEP flags require additional arithmetic semantics')
            base = self.pointer(expression['base'])
            offset, poison, ub = base.offset.bits, base.offset.poison, base.offset.ub
            all_zero, checks = [], []
            obj = self.initial.objects.get(base.object_id)
            checks.append(z3.BoolVal(False) if obj is None else z3.ULE(offset, obj.size))
            for term in expression['offset_terms']:
                if 'field' in term:
                    if term.get('offset_bytes') is None:
                        raise UnsupportedLLVM('missing struct layout')
                    delta = z3.BitVecVal(term['offset_bytes'], 64)
                    all_zero.append(z3.BoolVal(term['field'] == 0))
                else:
                    if term.get('scale_bytes') is None:
                        raise UnsupportedLLVM('missing GEP stride')
                    index = self.evaluate(term['index'])
                    if not isinstance(index, Scalar):
                        raise UnsupportedLLVM('noninteger GEP index')
                    width = index.bits.size()
                    if width > 64:
                        raise UnsupportedLLVM('GEP index wider than the supported 64-bit profile')
                    bits = z3.SignExt(64-width, index.bits) if width < 64 else z3.Extract(63, 0, index.bits)
                    all_zero.append(index.bits == 0)
                    delta = bits*term['scale_bytes']
                    poison, ub = z3.Or(poison, index.poison), z3.Or(ub, index.ub)
                    checks.append(z3.SignExt(64, bits)*term['scale_bytes'] == z3.SignExt(64, delta))
                    if flags & 4:
                        checks.append(z3.ZeroExt(64, bits)*term['scale_bytes'] == z3.ZeroExt(64, delta))
                new = offset+delta
                checks.append(z3.SignExt(64, offset)+z3.SignExt(64, delta) == z3.SignExt(64, new))
                if flags & 4:
                    checks.append(z3.ZeroExt(64, offset)+z3.ZeroExt(64, delta) == z3.ZeroExt(64, new))
                checks.append(z3.BoolVal(False) if obj is None else z3.ULE(new, obj.size))
                offset = new
            if expression.get('inbounds'):
                poison = z3.Or(poison, z3.Not(z3.Or(z3.And(*all_zero), z3.And(*checks))))
            return Pointer(base.object_id, Scalar(offset, poison, ub))
        if op == 'load':
            if expression.get('volatile') or expression.get('atomic_ordering'):
                raise UnsupportedLLVM('volatile/atomic load requires additional semantics')
            if expression['value_type'].get('integer_bits') is None:
                raise UnsupportedLLVM('pointer/aggregate loads require additional semantics')
            state = self.memory(expression['memory'])
            pointer = self.pointer(expression['address'])
            valid = self.access(state, pointer, expression['size_bytes'], expression['alignment'])
            if pointer.object_id not in state.objects:
                # Return an arbitrary value under an unconditional UB obligation.
                return Scalar(self.fresh(expression['value_type']['integer_bits']), ub=z3.BoolVal(True))
            value = state.objects[pointer.object_id].memory.load(pointer.offset.bits, expression['value_type']['integer_bits'])
            return Scalar(value.bits, value.poison, z3.Or(state.ub, pointer.offset.ub, pointer.offset.poison, z3.Not(valid)))
        if op in ('ptrtoint', 'inttoptr', 'addrspacecast'):
            raise UnsupportedLLVM('pointer/integer/address-space casts are outside the object-pointer profile')
        if op == 'bitcast' and expression.get('type', {}).get('llvm') == 'ptr':
            return self.pointer(expression['operands'][0])
        if op == 'icmp':
            x, y = [self.evaluate(v) for v in expression['operands']]
            if isinstance(x, Pointer) or isinstance(y, Pointer):
                if not isinstance(x, Pointer) or not isinstance(y, Pointer) or expression['predicate'] not in ('eq', 'ne'):
                    raise UnsupportedLLVM('only equality comparisons of object pointers are implemented')
                if x.object_id != y.object_id:
                    raise UnsupportedLLVM('cross-object equality needs concrete placement/adjacency semantics')
                equal = z3.And(z3.BoolVal(x.object_id == y.object_id), x.offset.bits == y.offset.bits)
                result = equal if expression['predicate'] == 'eq' else z3.Not(equal)
                return Scalar(z3.If(result, z3.BitVecVal(1, 1), z3.BitVecVal(0, 1)),
                              z3.Or(x.offset.poison, y.offset.poison), z3.Or(x.offset.ub, y.offset.ub))
        if op == 'select' and expression.get('type', {}).get('llvm') == 'ptr':
            condition, x, y = [self.evaluate(v) for v in expression['operands']]
            if not isinstance(x, Pointer) or not isinstance(y, Pointer) or x.object_id != y.object_id:
                raise UnsupportedLLVM('select between distinct objects requires a symbolic provenance domain')
            choose = condition.bits == 1
            return Pointer(x.object_id, Scalar(z3.If(choose, x.offset.bits, y.offset.bits),
                z3.Or(condition.poison, z3.If(choose, x.offset.poison, y.offset.poison)),
                z3.Or(condition.ub, x.offset.ub, y.offset.ub)))
        return super().evaluate(expression)

    def memory(self, expression):
        if expression.get('kind') == 'entry_memory':
            return self.initial
        if expression.get('operator') != 'store':
            raise UnsupportedLLVM('unknown memory relation')
        if expression.get('volatile') or expression.get('atomic_ordering'):
            raise UnsupportedLLVM('volatile/atomic store requires additional semantics')
        state = self.memory(expression['memory'])
        pointer = self.pointer(expression['address'])
        value = self.evaluate(expression['value'])
        if not isinstance(value, Scalar) or value.bits.size() != expression['value_type'].get('integer_bits'):
            raise UnsupportedLLVM('only scalar integer stores are supported')
        valid = self.access(state, pointer, expression['size_bytes'], expression['alignment'])
        objects = dict(state.objects)
        if pointer.object_id in objects:
            obj = objects[pointer.object_id]
            objects[pointer.object_id] = MemoryObject(obj.memory.store(pointer.offset.bits, value), obj.size, obj.alignment)
        return MemoryState(objects, z3.Or(state.ub, pointer.offset.ub, pointer.offset.poison, value.ub, z3.Not(valid)))
