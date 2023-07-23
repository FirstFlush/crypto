class VigenereCipher(object):

    def __init__(self, key:str, alphabet:str=None):

        self.key = key
        self.alphabet = alphabet
        if self.alphabet is None:
            self.alphabet = 'abcdefghijklmnopqrstuvwxyz'

    
    def _signing_key(self, text:str) -> str:
        signing_key = ''
        while len(signing_key) < len(text):
            signing_key += self.key
        return signing_key[:len(text)]


    def encode(self, text):

        signing_key = self._signing_key(text)
        encoded_msg = ''
        for i, char in enumerate(text):
            alphabet_index = self.alphabet.find(char)
            if alphabet_index == -1:
                encoded_msg += char
            else:
                shift = (self.alphabet.find(signing_key[i]))
                encoded_msg += self.alphabet[(alphabet_index + shift) % len(self.alphabet)]

        return encoded_msg


    def decode(self, text):
        signing_key = self._signing_key(text)
        decoded_msg = ''
        for i, char in enumerate(text):
            alphabet_index = self.alphabet.find(char)
            if alphabet_index == -1:
                decoded_msg += char
            else:
                shift = (self.alphabet.find(signing_key[i]))
                decoded_msg += self.alphabet[(self.alphabet.find(char) - shift) % len(self.alphabet)]
        
        return decoded_msg



# cipher = VigenereCipher('password').encode('hello how are you todayfdaszz')
# cipher = VigenereCipher('password').decode('weddk yrl sja prj lgzopisakrv')