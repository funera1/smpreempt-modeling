"""SMT semantics for a scalar LLVM subset and raw byte-memory operations.

Not a full LLVM interpreter. Pointer provenance, lifetimes, alignment and valid
memory ranges must be supplied by a caller; unresolved expressions raise errors.
"""
from dataclasses import dataclass, field
import z3


class UnsupportedLLVM(ValueError):
    pass


@dataclass(frozen=True)
class Scalar:
    bits: object
    poison: object = field(default_factory=lambda: z3.BoolVal(False))
    ub: object = field(default_factory=lambda: z3.BoolVal(False))

    @property
    def defined(self):
        return z3.And(z3.Not(self.ub), z3.Not(self.poison))


def scalar(value, width):
    return Scalar(z3.BitVecVal(value, width))


class ScalarSemantics:
    def __init__(self, values=None, prefix='llvm', predecessor=None):
        self.values = {} if values is None else dict(values)
        self.prefix, self.counter = prefix, 0
        self.predecessor, self.freeze_values = predecessor, {}

    def fresh(self, width):
        self.counter += 1
        return z3.BitVec(f'{self.prefix}_choice_{self.counter}', width)

    def evaluate(self, expression):
        kind = expression.get('kind')
        if kind == 'reference':
            try:
                value = self.values[expression['id']]
                if not isinstance(value, Scalar):
                    raise UnsupportedLLVM('SSA value is not an integer scalar')
                return value
            except KeyError as exc:
                raise UnsupportedLLVM('unbound SSA value: '+expression['id']) from exc
        if kind in ('literal', 'undef', 'poison'):
            width = expression['type'].get('integer_bits')
            if width is None:
                raise UnsupportedLLVM('only integer literals are executable here')
            if kind == 'poison':
                return Scalar(self.fresh(width), z3.BoolVal(True))
            if kind == 'undef':
                return Scalar(self.fresh(width))  # a distinct choice on each use
            if 'bits_unsigned' not in expression:
                raise UnsupportedLLVM('unknown integer literal')
            return scalar(int(expression['bits_unsigned']), width)
        op = expression.get('operator')
        flags = expression.get('flags', {})
        operands = expression.get('operands', [])
        if op == 'phi_select':
            incoming = [i for i in expression['incoming'] if i['predecessor'] == self.predecessor]
            if len(incoming) != 1:
                raise UnsupportedLLVM('PHI requires one explicitly selected predecessor')
            return self.evaluate(incoming[0]['value'])
        if op == 'not':
            x = self.evaluate(expression['operand'])
            if x.bits.size() != 1:
                raise UnsupportedLLVM('condition negation requires i1')
            return Scalar(~x.bits, x.poison, x.ub)
        if op == 'eq':
            return self.evaluate(dict(operator='icmp', predicate='eq', operands=operands))
        if op == 'not_in':
            x = self.evaluate(expression['value'])
            cases = [self.evaluate(c) for c in expression['cases']]
            result = z3.And(*[x.bits != c.bits for c in cases])
            return Scalar(z3.If(result, z3.BitVecVal(1, 1), z3.BitVecVal(0, 1)),
                          z3.Or(x.poison, *[c.poison for c in cases]), z3.Or(x.ub, *[c.ub for c in cases]))
        if op == 'freeze':
            binding = expression.get('ssa_binding')
            if binding in self.freeze_values:
                return self.freeze_values[binding]
            value = self.evaluate(operands[0])
            result = Scalar(z3.If(value.poison, self.fresh(value.bits.size()), value.bits), ub=value.ub)
            if binding is not None:
                self.freeze_values[binding] = result
            return result
        if op == 'select':
            c, x, y = [self.evaluate(v) for v in operands]
            if c.bits.size() != 1 or x.bits.size() != y.bits.size():
                raise UnsupportedLLVM('invalid scalar select types')
            choose = c.bits == 1
            return Scalar(z3.If(choose, x.bits, y.bits),
                          z3.Or(c.poison, z3.If(choose, x.poison, y.poison)),
                          z3.Or(c.ub, x.ub, y.ub))
        if op in ('trunc', 'zext', 'sext', 'bitcast'):
            x = self.evaluate(operands[0])
            width = expression['type'].get('integer_bits')
            if width is None:
                raise UnsupportedLLVM('pointer/floating casts require additional semantics')
            old = x.bits.size()
            if op == 'trunc' and width < old:
                bits = z3.Extract(width-1, 0, x.bits)
            elif op == 'zext' and width > old:
                bits = z3.ZeroExt(width-old, x.bits)
            elif op == 'sext' and width > old:
                bits = z3.SignExt(width-old, x.bits)
            elif op == 'bitcast' and width == old:
                bits = x.bits
            else:
                raise UnsupportedLLVM('invalid scalar cast widths')
            poison = x.poison
            if op == 'zext' and flags.get('nneg'):
                poison = z3.Or(poison, x.bits < 0)
            if op == 'trunc':
                if flags.get('nuw'):
                    poison = z3.Or(poison, z3.ZeroExt(old-width, bits) != x.bits)
                if flags.get('nsw'):
                    poison = z3.Or(poison, z3.SignExt(old-width, bits) != x.bits)
            return Scalar(bits, poison, x.ub)
        if op not in ('add', 'sub', 'mul', 'and', 'or', 'xor', 'shl', 'lshr', 'ashr',
                      'udiv', 'sdiv', 'urem', 'srem', 'icmp'):
            raise UnsupportedLLVM('unimplemented expression: '+str(op))
        x, y = [self.evaluate(v) for v in operands]
        if x.bits.size() != y.bits.size():
            raise UnsupportedLLVM('mismatched scalar operand widths')
        a, b, width = x.bits, y.bits, x.bits.size()
        poison, ub = z3.Or(x.poison, y.poison), z3.Or(x.ub, y.ub)
        flags = expression.get('flags', {})
        if op == 'icmp':
            p = expression['predicate']
            predicates = {'eq': a == b, 'ne': a != b, 'ugt': z3.UGT(a, b), 'uge': z3.UGE(a, b),
                          'ult': z3.ULT(a, b), 'ule': z3.ULE(a, b), 'sgt': a > b,
                          'sge': a >= b, 'slt': a < b, 'sle': a <= b}
            return Scalar(z3.If(predicates[p], z3.BitVecVal(1, 1), z3.BitVecVal(0, 1)), poison, ub)
        operations = {'add': lambda: a+b, 'sub': lambda: a-b, 'mul': lambda: a*b,
                      'and': lambda: a & b, 'or': lambda: a | b, 'xor': lambda: a ^ b,
                      'shl': lambda: a << b, 'lshr': lambda: z3.LShR(a, b), 'ashr': lambda: a >> b,
                      'udiv': lambda: z3.UDiv(a, b), 'sdiv': lambda: a / b,
                      'urem': lambda: z3.URem(a, b), 'srem': lambda: z3.SRem(a, b)}
        bits = operations[op]()
        if op == 'or' and flags.get('disjoint'):
            poison = z3.Or(poison, (a & b) != 0)
        if op in ('add', 'sub', 'mul', 'shl'):
            if flags.get('nuw'):
                aa, bb = z3.ZeroExt(width, a), z3.ZeroExt(width, b)
                wide = {'add': lambda: aa+bb, 'sub': lambda: aa-bb,
                        'mul': lambda: aa*bb, 'shl': lambda: aa << bb}[op]()
                poison = z3.Or(poison, wide != z3.ZeroExt(width, bits))
            if flags.get('nsw'):
                aa = z3.SignExt(width, a)
                bb = z3.ZeroExt(width, b) if op == 'shl' else z3.SignExt(width, b)
                wide = {'add': lambda: aa+bb, 'sub': lambda: aa-bb,
                        'mul': lambda: aa*bb, 'shl': lambda: aa << bb}[op]()
                poison = z3.Or(poison, wide != z3.SignExt(width, bits))
        if op in ('shl', 'lshr', 'ashr'):
            poison = z3.Or(poison, z3.UGE(b, width))
            if flags.get('exact'):
                poison = z3.Or(poison, (bits << b) != a)
        if op in ('udiv', 'sdiv', 'urem', 'srem'):
            ub = z3.Or(ub, y.poison, b == 0)
            if op in ('sdiv', 'srem'):
                ub = z3.Or(ub, z3.And(z3.Not(x.poison), a == (1 << (width-1)), b == (1 << width)-1))
            if flags.get('exact'):
                remainder = z3.URem(a, b) if op == 'udiv' else z3.SRem(a, b)
                poison = z3.Or(poison, remainder != 0)
        return Scalar(bits, poison, ub)

    def branch_guard(self, expression, taken=True):
        value = self.evaluate(expression)
        if value.bits.size() != 1:
            raise UnsupportedLLVM('branch condition is not scalar i1')
        return z3.And(value.defined, value.bits == (1 if taken else 0))


@dataclass(frozen=True)
class ByteMemory:
    data: object
    poison: object

    @classmethod
    def fresh(cls, name, address_bits=64):
        index = z3.BitVecSort(address_bits)
        return cls(z3.Array(name, index, z3.BitVecSort(8)), z3.K(index, z3.BoolVal(False)))

    def store(self, address, value):
        if value.bits.size() % 8:
            raise UnsupportedLLVM('byte memory currently requires widths divisible by 8')
        data, poison = self.data, self.poison
        for i in range(value.bits.size()//8):
            data = z3.Store(data, address+i, z3.Extract(i*8+7, i*8, value.bits))
            poison = z3.Store(poison, address+i, value.poison)
        return ByteMemory(data, poison)

    def load(self, address, width):
        if width < 8 or width % 8:
            raise UnsupportedLLVM('byte memory currently requires widths divisible by 8')
        data = z3.Concat(*[z3.Select(self.data, address+i) for i in reversed(range(width//8))]) if width > 8 else z3.Select(self.data, address)
        return Scalar(data, z3.Or(*[z3.Select(self.poison, address+i) for i in range(width//8)]))
