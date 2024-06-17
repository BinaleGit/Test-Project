from col import set_simp_called

def add_numbers(a, b):
    set_simp_called()
    return a + b

def subtract_numbers(a, b):
    set_simp_called()
    return a - b