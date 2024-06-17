from functools import reduce
from col import check_simp_called

def sum_of_digits(number):
    check_simp_called()
    return sum(map(int, str(number)))

def is_palindrome(number):
    check_simp_called()
    str_number = str(number)
    return str_number == str_number[::-1]