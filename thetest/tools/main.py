from numbers.comp import sum_of_digits, is_palindrome
from numbers.simp import add_numbers, subtract_numbers
from col import my_zip, check_simp_called, set_simp_called

# Print the results 
print("Add:", add_numbers(78, 28))
print("Subtraction:", subtract_numbers(15,7))
print("sum:", sum_of_digits(583))
print(" palindrome:", is_palindrome(4567))
print("Zipp:", my_zip([1, 2, 3], ['Roee', 'May', 'Eyal']))
