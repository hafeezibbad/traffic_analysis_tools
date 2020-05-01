import binascii
import ipaddress
from logging import getLogger

import dpkt

DOMAIN_NAME_COMPRESSION = 0xA0

LOGGING = getLogger(__name__)


class Mdns:
    """
    A class to decode a mDNS message.

    Because the DPKT library is such a mess, documentation wise :(
    """

    def advance(self, bytecount):
        self.pointer += bytecount

    def read_int_16(self):

        LOGGING.debug("%s Reading 16 bit integer", self.pointer)

        i = int.from_bytes(self.buffer[self.pointer: self.pointer + 2], byteorder="big")
        self.advance(2)

        return i

    def read_int_32(self):
        LOGGING.debug("%s Reading 32 bit integer", self.pointer)
        i = int.from_bytes(
            self.buffer[self.pointer: self.pointer + 4], byteorder="big"
        )
        self.advance(4)
        return i

    def read_short_string(self):
        LOGGING.debug("%s Reading short string", self.pointer)

        if self.pointer > len(self.buffer):
            return False, ""

        length = self.buffer[self.pointer]

        if length & DOMAIN_NAME_COMPRESSION:

            LOGGING.debug("%s Domain name compression!", self.pointer)
            # Read the 2 byte
            # locator for the domain name string we want to reuse.
            # Remember to ignore the first 2 bits which are the flag.
            location = self.read_int_16() & 0x3FFF
            # Now save current location, then go back and read the domain name
            # from the pointed location. Then come back to where we were

            LOGGING.debug("%s Rereading to %s", self.pointer, location)
            # NOTE: I have no idea how to handle this. Paulo.
            # if location >= self.pointer:
            #     LOGGING.debug("Not back to the future!")
            #     # return False, ''
            #     abort(500)
            oldpointer = self.pointer
            self.pointer = location
            name = self.read_domain()
            self.pointer = oldpointer

            LOGGING.debug("%s Returned to here", self.pointer)

            return True, name.encode("utf-8")

        string = self.buffer[self.pointer + 1: self.pointer + length + 1]

        LOGGING.debug("%s mDNS string (len %s): %s", self.pointer, len(string), string)
        self.advance(length + 1)

        return False, string

    def read_domain(self):
        """Read a list of strings and return a dot separated name list"""
        LOGGING.debug("%s Reading domain", self.pointer)
        strings = list()

        while True:
            last, s = self.read_short_string()

            if not s:
                break

            try:
                decoded = s.decode("utf-8")

            except UnicodeDecodeError:
                decoded = s.decode("cp1252")
            strings.append(decoded)

            if last:
                break

        name = ".".join(strings)

        LOGGING.debug("%s Domain name was %s", self.pointer, name)

        return name

    def read_long_string(self):
        """Get 16 bits of data length and then the data"""
        length = self.read_int_16()

        LOGGING.debug("%s Reading long string", self.pointer)

        string = self.buffer[self.pointer: self.pointer + length + 1]
        self.advance(length)

        LOGGING.debug("%s Finished long string", self.pointer)

        return string

    def read_question(self):
        LOGGING.debug("%s Reading Question", self.pointer)
        question = dict()
        question["QNAME"] = self.read_domain()
        question["QTYPE"] = self.read_int_16()
        qclass = self.read_int_16()
        question["QCLASS"] = qclass & 0x7FFF
        question["UNICAST-RESPONSE"] = (qclass >> 15) & 0x1

        LOGGING.debug("%s Finished Question", self.pointer)

        return question

    def read_resource(self):  # noqa
        LOGGING.debug("%s Reading RR", self.pointer)
        question = dict()
        question["NAME"] = self.read_domain()
        question["TYPE"] = self.read_int_16()
        rrclass = self.read_int_16()
        question["CLASS"] = rrclass & 0x7FFF
        question["CACHE-FLUSH"] = (rrclass >> 15) & 0x1
        question["TTL"] = self.read_int_32()

        if question["TYPE"] == dpkt.dns.DNS_PTR:
            question["typestring"] = "PTR"

            LOGGING.debug("%s Reading %s", self.pointer, question["typestring"])
            question["RDLENGTH"] = self.read_int_16()
            out_of_bounds = self.pointer + question["RDLENGTH"]
            question["PTRDNAME"] = self.read_domain()

            if self.pointer < out_of_bounds:
                LOGGING.debug("%s Unused RDATA", self.pointer)
                question["RDATA"] = self.buffer[self.pointer: out_of_bounds]
                self.pointer = out_of_bounds

        elif question["TYPE"] == dpkt.dns.DNS_SRV:
            question["typestring"] = "SRV"

            LOGGING.debug("%s Reading %s", self.pointer, question["typestring"])
            question["RDLENGTH"] = self.read_int_16()
            out_of_bounds = self.pointer + question["RDLENGTH"]
            question["PRIO"] = self.read_int_16()
            question["WEIGHT"] = self.read_int_16()
            question["PORT"] = self.read_int_16()
            question["TARGET"] = self.read_domain()

            if self.pointer < out_of_bounds:
                LOGGING.debug("%s Unused RDATA", self.pointer)
                question["RDATA"] = self.buffer[self.pointer: out_of_bounds]
                self.pointer = out_of_bounds

        elif question["TYPE"] == dpkt.dns.DNS_AAAA:
            question["typestring"] = "AAAA"

            LOGGING.debug("%s Reading %s", self.pointer, question["typestring"])
            question["RDLENGTH"] = self.read_int_16()
            out_of_bounds = self.pointer + question["RDLENGTH"]

            if question["RDLENGTH"] == 16:
                question["IPv6"] = ipaddress.IPv6Address(
                    self.buffer[self.pointer: out_of_bounds]
                )

            LOGGING.debug("%s No 16 bytes in ipv6 address", self.pointer)
            question["RDATA"] = self.buffer[self.pointer: out_of_bounds]
            self.pointer = out_of_bounds

        elif question["TYPE"] == dpkt.dns.DNS_TXT:
            question["typestring"] = "TXT"

            LOGGING.debug("%s Reading %s", self.pointer, question["typestring"])
            # for TXT this is a list of strings, not always ending with empty
            # string
            question["RDLENGTH"] = self.read_int_16()

            LOGGING.debug("%s Length of text %s", self.pointer, question["RDLENGTH"])
            out_of_bounds = self.pointer + question["RDLENGTH"]
            strings = list()

            while self.pointer < out_of_bounds:
                end, s = self.read_short_string()

                if end or not s:
                    break

                strings.append(s.decode("utf-8"))

            question["TXT-RDATA"] = strings

            if self.pointer < out_of_bounds:
                LOGGING.debug("%s Unused RDATA", self.pointer)
                question["RDATA"] = self.buffer[self.pointer: out_of_bounds]
                self.pointer = out_of_bounds

        else:

            LOGGING.debug("%s Reading unknown RR type", self.pointer)
            question["RDATA"] = self.read_long_string()

        LOGGING.debug("%s Finished RR", self.pointer)

        return question

    def interpret_flags(self, bits):
        #                                 1  1  1  1  1  1
        #   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
        # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        # |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
        flags = dict()
        flags["RCODE"] = bits & 0xF
        bits = bits >> 4
        flags["Z"] = bits & 0x7
        bits = bits >> 3
        flags["RA"] = bits & 0x1
        bits = bits >> 1
        flags["RD"] = bits & 0x1
        bits = bits >> 1
        flags["TC"] = bits & 0x1
        bits = bits >> 1
        flags["AA"] = bits & 0x1
        bits = bits >> 1
        flags["OPCODE"] = bits & 0xF
        bits = bits >> 4
        flags["QR"] = bits & 0x1

        return flags

    def __init__(self, buffer_bytes):
        """Keep buffer and current pointer in common storage"""
        self.buffer = buffer_bytes
        self.pointer = 0

        LOGGING.debug("%s mdns bytes: %s", self.pointer, binascii.hexlify(self.buffer))

        LOGGING.debug("%s Reading header", self.pointer)

        self.transaction_id = self.read_int_16()
        self.flags = self.interpret_flags(self.read_int_16())
        self.question_count = self.read_int_16()
        self.answer_count = self.read_int_16()
        self.authority_count = self.read_int_16()
        self.additional_count = self.read_int_16()
        LOGGING.debug(
            "%s %s questions, %s answers, %s authorities, %s additionals",
            self.pointer,
            self.question_count,
            self.answer_count,
            self.authority_count,
            self.additional_count,
        )
        LOGGING.debug("%s Questions section", self.pointer)
        self.questions = list()

        for i in range(self.question_count):
            q = self.read_question()
            self.questions.append(q)

        LOGGING.debug("%s Answers section", self.pointer)
        self.answers = list()

        for i in range(self.answer_count):
            q = self.read_resource()
            self.answers.append(q)

        LOGGING.debug("%s Authorities section", self.pointer)
        self.authorities = list()

        for i in range(self.authority_count):
            q = self.read_resource()
            self.authorities.append(q)

        LOGGING.debug("%s Additionals section", self.pointer)
        self.additionals = list()

        for i in range(self.additional_count):
            q = self.read_resource()
            self.additionals.append(q)

    def is_response(self):
        return self.flags["QR"] == dpkt.dns.DNS_R

    def is_query(self):
        return self.flags["OPCODE"] == dpkt.dns.DNS_QUERY

    def has_error(self):
        return self.flags["RCODE"] != dpkt.dns.DNS_RCODE_NOERR
