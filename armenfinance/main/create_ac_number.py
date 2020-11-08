import random 
import string 

def accountNumber():
    number = ''.join(random.choices(string.digits, k=9))
    
    return '41' + number