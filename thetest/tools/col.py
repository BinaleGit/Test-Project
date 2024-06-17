simp_called = False

def check_simp_called():
    global simp_called
    if not simp_called:
        raise Exception("You must call at least one function in simp module before calling functions in comp module.")

def set_simp_called():
    global simp_called
    simp_called = True

def my_zip(it1, it2):
    return list(zip(it1, it2))