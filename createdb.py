#!/usr/bin/env python3
# -*- encoding: utf-8 -*-
import sqlite3

database = sqlite3.connect("./stats.db")
cursor = database.cursor()

cursor.execute('PRAGMA foreign_keys = 1')

cursor.execute('DROP TABLE IF EXISTS history')

cursor.execute("CREATE TABLE history (id INTEGER PRIMARY KEY AUTOINCREMENT, artist_id INT, artist_name TEXT, title_id INT, title_name TEXT, played_at DATETIME UNIQUE )")

database.commit()

database.close()
