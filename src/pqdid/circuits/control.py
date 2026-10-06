"""Active-path rejection, branch muxes and fixed-capacity private indexing.

This is a gadget API, not a Python AST compiler or complete sampler-loop lowerer.
"""

from collections.abc import Callable

from pqdid.circuits.emitter import Bit, Emitter
from pqdid.circuits.words import Checked, Word, check_word, constant, equal, mux_word


class Scope:
    def __init__(self, emitter: Emitter, *, active: Bit | None = None):
        self.e = emitter
        self.active = emitter.one if active is None else active
        emitter.check_bit(self.active)
        self.rejected = emitter.zero

    def require(self, condition: Bit):
        fault = self.e.and_(self.active, self.e.not_(condition))
        self.rejected = self.e.or_(self.rejected, fault)

    def checked(self, result: Checked) -> Word:
        self.require(result.valid)
        return result.value

    def output(self, checks: tuple[Bit, ...]) -> Bit:
        if type(checks) is not tuple:
            raise ValueError("checks must be an ordered tuple")
        result = self.e.one
        for check in checks:
            result = self.e.and_(result, check)
        return self.e.and_(result, self.e.not_(self.rejected))

    def branch(self, selector: Bit, when_true: Callable, when_false: Callable) -> Word:
        true_scope = Scope(self.e, active=self.e.and_(self.active, selector))
        true_value = when_true(true_scope)
        false_scope = Scope(self.e, active=self.e.and_(self.active, self.e.not_(selector)))
        false_value = when_false(false_scope)
        # Both branches exist, irrespective of the private selector's evaluation.
        self.rejected = self.e.or_(self.rejected, true_scope.rejected)
        self.rejected = self.e.or_(self.rejected, false_scope.rejected)
        return mux_word(self.e, selector, false_value, true_value)

    def _array(self, cells: tuple[Word, ...], index: Word):
        check_word(self.e, index, 64)
        if type(cells) is not tuple or not 1 <= len(cells) <= 1024:
            raise ValueError("development array requires 1 to 1024 fixed cells")
        check_word(self.e, cells[0])
        for cell in cells:
            check_word(self.e, cell, len(cells[0]))

    def read(self, cells: tuple[Word, ...], index: Word) -> Word:
        self._array(cells, index)
        found = self.e.zero
        value = (self.e.zero,) * len(cells[0])
        for position, cell in enumerate(cells):
            match = equal(self.e, index, constant(self.e, position, 64))
            found = self.e.or_(found, match)
            selected = self.e.and_(self.active, match)
            value = mux_word(self.e, selected, value, cell)
        self.require(found)
        return value

    def write(self, cells: tuple[Word, ...], index: Word, value: Word) -> tuple[Word, ...]:
        self._array(cells, index)
        check_word(self.e, value, len(cells[0]))
        snapshot = cells
        found = self.e.zero
        result = []
        for position, cell in enumerate(snapshot):
            match = equal(self.e, index, constant(self.e, position, 64))
            found = self.e.or_(found, match)
            selected = self.e.and_(self.active, match)
            result.append(mux_word(self.e, selected, cell, value))
        self.require(found)
        return tuple(result)
