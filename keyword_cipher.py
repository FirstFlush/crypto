abc = "abcdefghijklmnopqrstuvwxyz"
key = "keywoordo"
# => keywordabcfghijlmnpqstuvxz


class KeywordCipher:

    def __init__(self, alphabet:str, keyword:str):
        self.abc = alphabet
        keyword_letters = ''.join(dict.fromkeys(keyword))        
        self.keyword = ''.join([letter for letter in keyword_letters if letter in self.abc])
        self.abc_new = f"{self.keyword}{''.join([char for char in self.abc if char not in self.keyword])}"
        print(self.abc_new)

    def encode(self, plain:str) -> str:
        encoded = ''
        for letter in plain:
            letter_index = self.abc.find(letter.lower())
            if letter_index >= 0:
                encoded += self.abc_new[letter_index]
            else:
                encoded += letter

        return encoded


    def decode(self, ciphered:str):
        decoded = ''
        for letter in ciphered:
            letter_index = self.abc_new.find(letter.lower())
            if letter_index == -1:
                decoded += letter
            else:
                decoded += self.abc[letter_index]
        return decoded


kc = KeywordCipher(abc, key)
print(kc.encode('hello world'))
print(kc.decode('aoggj ujngw'))


