import os
import pyasn1
from pyasn1.type import * 
from pyasn1.type.namedtype import * 
from pyasn1.type.univ import * 
from pyasn1.type.char import * 
from pyasn1.codec.der.encoder import encode

class Record(Sequence):
    componentType = NamedTypes(
        NamedType('int0', Integer()),
        NamedType('intneg', Integer()),
        NamedType('int_large', Integer()),
        NamedType('printable', PrintableString()),
        NamedType('ia5', IA5String()),
        NamedType('utf8', UTF8String()),
        NamedType('bit', BitString()),
        NamedType('bit_large', BitString()),
    )

r = Record()
r['int0'] = 0
r['intneg'] = -137878
r['int_large'] = 12323232312121783738263
r['printable'] = "printable string"
r['ia5'] = "is5 string"
r['utf8'] = "αβγδ"
r['bit'] = "01001"
r['bit_large'] = "010011110010011000000110"

os.write(1, encode(r))
