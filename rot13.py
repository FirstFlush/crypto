
def rot13(message:str):
    
    alphabet = 'abcdefghijklmnopqrstuvwxyz '

    encoded = ''
    for char in message:
        if char.isalpha():
            i = alphabet.find(char.lower())
            new_char = alphabet[(i + 13) % 26]
            if char.isupper():
                new_char = new_char.upper()
            char = new_char
        encoded += char
    return encoded



print(rot13("EBG13 rknzcyr."))
