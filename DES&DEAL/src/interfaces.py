from abc import ABC, abstractmethod


class IKeyExpansion(ABC):
    @abstractmethod
    def generate_round_keys(self, key): pass
        

class IEncryptor(ABC):
    @abstractmethod
    def Feistel_function(self, input_block, round_key): pass
        
    @abstractmethod
    async def Feistel_function_async(self, input_block, round_key): pass
        

class ISymmetricCipher(ABC):
    @property
    @abstractmethod
    def block_size(self): pass
        
    @abstractmethod
    def encrypt_block(self, block): pass
    
    @abstractmethod
    def decrypt_block(self, block): pass
    
    @abstractmethod
    async def encrypt_block_async(self, block): pass

    @abstractmethod
    async def decrypt_block_async(self, block): pass


class IFeistelNetwork(ISymmetricCipher):
    @property
    @abstractmethod
    def rounds(self): pass
        
    @abstractmethod
    def set_round_keys(self, round_keys): pass
    
    @abstractmethod
    def generate_round_keys(self, key): pass
    

class IDESAdapter(ABC):
    @property
    @abstractmethod
    def block_size(self): pass
    
    @abstractmethod
    def encrypt_block(self, block): pass
    
    @abstractmethod
    def decrypt_block(self, block): pass
    
    @abstractmethod
    async def encrypt_block_async(self, block): pass
    
    @abstractmethod
    async def decrypt_block_async(self, block): pass
