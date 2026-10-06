"""Counted half-open coverage metadata; no claim to partitioned proof composition."""


def validate_coverage(parts, *, rows, variables):
    if type(parts) is not tuple or not parts:
        raise ValueError("nonempty immutable coverage schedule")
    if type(rows) is not int or type(variables) is not int or rows < 1 or variables < 1:
        raise ValueError("positive final dimensions")
    previous_row = previous_variable = 0
    seen = set()
    for identifier, begin, end, var_begin, var_end in parts:
        if type(identifier) is not str or not identifier or identifier in seen:
            raise ValueError("missing or duplicate partition identity")
        if any(type(x) is not int for x in (begin, end, var_begin, var_end)):
            raise ValueError("exact integer coverage")
        if begin != previous_row or var_begin != previous_variable:
            raise ValueError("overlapping or missing coverage")
        if not begin < end <= rows or not var_begin <= var_end <= variables:
            raise ValueError("invalid interval")
        previous_row, previous_variable = end, var_end
        seen.add(identifier)
    if previous_row != rows or previous_variable != variables:
        raise ValueError("incomplete final coverage")
    return {"rows": rows, "variables": variables, "parts": len(parts), "overlap": 0}
