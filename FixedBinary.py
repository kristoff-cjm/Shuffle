class FixedBinary:
    def __init__(self, value, length=None):
        # Can be constructed with any number, bin() or hex() of a number,
        # or any string that can be represented as such
        # Can be constructed by another instance of itself
        if isinstance(value, int):
            binary_str = bin(value)[2:]
        elif isinstance(value, str):
            if value.startswith('0b'):
                #remove 0b prefix
                binary_str = value[2:]
            elif value.startswith('0x'):
                binary_str = bin(int(value, 16))[2:]
                if length is None:
                    #pad to the nearest /4 because 4 bits per hex character
                    binary_str = binary_str.zfill(len(binary_str) + 4 - len(binary_str)%4)
            else:
                binary_str = bin(int(value, 2))[2:]
                #no padding, assume binary string
        elif isinstance(value, bytes):
            binary_str = ''.join(format(byte, '08b') for byte in value)
            if length is None:
                length = len(binary_str)
        elif isinstance(value, FixedBinary):
            binary_str = value.value
            if length is None:
                length = value.length
        else:
            raise TypeError("This type is not supported: ", type(value))

        # If length is not provided, calculate it based on the value's binary length
        if length is None:
            length = len(binary_str)

        if length < len(binary_str):
            raise ValueError("Specified length is too small for the binary representation of the number.")

        if length > len(binary_str):
            #if specified length is > current length, pad out to length with 0s
            binary_str = binary_str.zfill(length)

        self.value = binary_str
        self.length = length
    
    def toHex(self):
        return hex(int(self.value, 2))
    
    def toUTF8(self):
        # Split the binary string into groups of 8 bits (1 byte)
        if self.length % 8 != 0:
            raise ValueError("The binary string's length must be a multiple of 8 to convert to UTF-8.")
        
        # Iterate over the binary string in chunks of 8 bits
        byte_list = [self.value[i:i+8] for i in range(0, self.length, 8)]
        
        # Convert each byte (8-bit binary string) to an integer, then to a character
        utf8_string = ''.join([chr(int(byte, 2)) for byte in byte_list])
        
        return utf8_string
    
    def __getitem__(self, index):
        #This allows indexing like a string with [] and slicing [:]
        if isinstance(index, slice):
            return self.value[index]
        
        return self.value[index]
    
    def __setitem__(self, index, bit):
        #This allows you to set a specific bit
        if bit not in ['0', '1', 0, 1]:
            raise ValueError("Bit value must be 0 or 1")
        
        bit = str(bit)
        self.value = self.value[:index] + bit + self.value[index + 1:]

    def __lshift__(self, steps):
        # Overload the left shift operator << with a circular shift
        if isinstance(steps, int):
            steps = steps % self.length
            p1 = self.value[:steps]
            rest = self.value[steps:]
            return FixedBinary(rest+p1, self.length)
        return NotImplemented

    def __rshift__(self, steps):
        # Overload the right shift operator >> with a circular shift
        if isinstance(steps, int):
            steps = steps % self.length
            steps = self.length - steps
            p1 = self.value[:steps]
            rest = self.value[steps:]
            return FixedBinary(rest+p1, self.length)
        return NotImplemented
    
    def __add__(self, other):
        # Allows you to CONCATENATE two FixedBinaries together
        if isinstance(other, FixedBinary):
            return FixedBinary((self.value + other.value), (self.length + other.length))
        return NotImplemented
    
    def __xor__(self, other):
        # Allows XOR addition on FixedBinary
        if isinstance(other, FixedBinary):
            return FixedBinary((int(self.value, 2) ^ int(other.value, 2)), self.length)
        return NotImplemented
    
    def __repr__(self):
        # When print() is used, displays the string value
        return f"bits: {self.value}, length: {self.length}"
    

def main():
    #Super Simple Example
    frombits = FixedBinary('0b1010')
    fromhex = FixedBinary('0x1234')
    fromString = FixedBinary("secrets".encode("utf-8"))
    fromInt = FixedBinary(12)

    #1234 -> 0001 0010 0011 0100

    print(frombits)
    print(fromhex)
    print(fromString)
    print(fromInt)


if (__name__ == "__main__"):
    main()