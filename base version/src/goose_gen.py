#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import time
import struct
from scapy.all import (
    Ether,
    Packet,
    ShortField,
    StrLenField,
    bind_layers,
    sendp
)

###############################################################################
# Класс GOOSE для генерации Ethernet II
###############################################################################
class GOOSE(Packet):
    name = "GOOSE"
    fields_desc = [
        ShortField("app_id", 0x0001),
        ShortField("length", 0),
        ShortField("reserved1", 0x0000),
        ShortField("reserved2", 0x0000),
        StrLenField("asn1", b"", length_from=lambda pkt: pkt.length - 8)
    ]

    def post_build(self, p, pay):
        if self.length == 0:
            total_len = len(p)
            p = p[:2] + struct.pack("!H", total_len) + p[4:]
        return p + pay

bind_layers(Ether, GOOSE, type=0x88B8)

###############################################################################
# Вспомогательные функции
###############################################################################
def pack_int32_5_bytes(value: int) -> bytes:
    sign_extension = 0x00 if value >= 0 else 0xFF
    int_bytes = struct.pack(">i", value)
    return bytes([sign_extension]) + int_bytes

def pack_float32(value: float) -> bytes:
    return struct.pack(">f", value)

def goose_time_bytes():
    now = time.time()
    now_sec = int(now)
    fraction = now - now_sec
    fraction_24 = int(fraction * (2**24))
    time_quality = 0
    val_64 = (now_sec << 32) | (fraction_24 << 8) | time_quality
    return struct.pack('>Q', val_64)

###############################################################################
# Функция сборки по ASN.1 блока GOOSE
###############################################################################
def build_goose_asn1(st_num, sq_num, goCBRef, datSet, goID, confRev, all_data):
    inside = b""

    # goCBRef
    inside += b"\x80" + bytes([len(goCBRef)]) + goCBRef.encode()
    # timeAllowedToLive
    inside += b"\x81\x02\x03\xe8"
    # datSet
    inside += b"\x82" + bytes([len(datSet)]) + datSet.encode()
    # goID
    inside += b"\x83" + bytes([len(goID)]) + goID.encode()

    # t (timestamp)
    t_bytes = goose_time_bytes()
    inside += b"\x84\x08" + t_bytes

    # stNum
    inside += b"\x85\x05" + pack_int32_5_bytes(st_num)

    # sqNum
    inside += b"\x86\x05" + pack_int32_5_bytes(sq_num)

    # simulation (false)
    inside += b"\x87\x01\x00"

    # confRev
    inside += b"\x88\x05" + pack_int32_5_bytes(confRev)

    # ndsCom (false)
    inside += b"\x89\x01\x00"

    # numDatSetEntries (4 элемента)
    inside += b"\x8a\x01\x04"

    # allData блок
    data_content = b""

    # 1. Boolean (аварийный сигнал)
    data_content += b"\x83\x01" + (b"\x01" if all_data[0] else b"\x00")

    # 2. INT32 (ток)
    data_content += b"\x85\x05" + pack_int32_5_bytes(int(all_data[1]))

    # 3. INT32 (напряжение)
    data_content += b"\x85\x05" + pack_int32_5_bytes(int(all_data[2]))

    # 4. INT32 (мощность)
    data_content += b"\x85\x05" + pack_int32_5_bytes(int(all_data[3]))

    all_data_block = b"\xab" + bytes([len(data_content)]) + data_content
    inside += all_data_block

    length_inside = len(inside)
    if length_inside < 128:
        goose_asn1 = b"\x61" + bytes([length_inside]) + inside
    else:
        goose_asn1 = b"\x61\x81" + bytes([length_inside]) + inside

    return goose_asn1

###############################################################################
# Функция формирования Ethernet/GOOSE
###############################################################################
def build_goose_packet(src_mac, dst_mac, st_num, sq_num, goCBRef, datSet, goID, confRev, all_data):
    asn1_data = build_goose_asn1(st_num, sq_num, goCBRef, datSet, goID, confRev, all_data)
    goose_layer = GOOSE(asn1=asn1_data)
    eth = Ether(dst=dst_mac, src=src_mac, type=0x88B8)
    return eth / goose_layer
