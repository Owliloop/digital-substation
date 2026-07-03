#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import yaml
import time
import random
from goose_gen import build_goose_packet
from scapy.all import sendp


#для запуска сразу нескольких
config_file = sys.argv[1] if len(sys.argv) > 1 else "conf_rza.yaml"


with open(config_file) as file:
    config = yaml.safe_load(file)

src_mac = config['src_mac']
dst_mac = config['dst_mac']
iface = config['iface']
goCBRef = config['goCBRef']
datSet = config['datSet']
goID = config['goID']
confRev = config['confRev']

alarm_state = config['initial_values']['alarm_state']
current = config['initial_values']['current']
voltage = config['initial_values']['voltage']
power = config['initial_values']['power']

st_num = 1
sq_num = 1

while True:
    # Случайная генерация аварийного состояния (с вероятностью 1%)
    alarm_state = random.random() < 0.01

    current = random.randint(20, 100)  # Ток в А
    voltage = random.randint(210, 250)  # Напряжение в В
    power = int((current * voltage) / 1000)  # Мощность в кВт

    # Подготовка данных для блока allData
    all_data = [
        alarm_state,  # Boolean (аварийное состояние)
        current,      # INT32 (ток)
        voltage,      # INT32 (напряжение)
        power         # INT32 (мощность)
    ]

    pkt = build_goose_packet(
        src_mac=src_mac,
        dst_mac=dst_mac,
        st_num=st_num,
        sq_num=sq_num,
        goCBRef=goCBRef,
        datSet=datSet,
        goID=goID,
        confRev=confRev,
        all_data=all_data
    )

    sendp(pkt, iface=iface, verbose=False)
    #pkt.show2()

    if alarm_state:
        print("[ALARM] Отправлен аварийный сигнал!")
        st_num += 1
        sq_num = 1
    else:
        print(f"[INFO] Данные отправлены: Ток={current}А, Напряжение={voltage}В, Мощность={power}кВт")
        sq_num += 1

    time.sleep(1)
