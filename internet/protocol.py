import binascii
import struct


class EthernetFrame:
    def __init__(self, destination: bytes, source: bytes, payload: bytes):
        if not (len(destination) == len(source) == 6):
            raise Exception('Mac address should be 6 octets long')
        self.destination = destination
        self.source = source
        self.payload = payload

    @staticmethod
    def from_bytes(data: bytes):
        destination = data[:6]
        source = data[6:12]
        length = struct.unpack('!H', data[12:14])[0]
        payload = data[14:14+length]
        print(data[14+length:], len(data[14+length:]))
        crc = struct.unpack('!I', data[14+length:])[0]
        if crc == binascii.crc32(data[:14+length]):
            return EthernetFrame(destination, source, payload)

    def to_bytes(self) -> bytes:
        data_without_crc = self.destination + self.source + \
                           struct.pack('!H', len(self.payload)) + \
                           self.payload
        crc = binascii.crc32(data_without_crc)
        return data_without_crc + struct.pack('!I', crc)

    def __eq__(self, other):
        return self.destination == other.destination and \
            self.source == other.source and self.payload == other.payload


if __name__ == '__main__':
    frame = EthernetFrame(b'abcdef', b'123456', b'datadatadatadatadatadata')
    if EthernetFrame.from_bytes(frame.to_bytes()) != frame:
        raise Exception('EthernetFrame is implemented wrong')
    print('All tests passed')
