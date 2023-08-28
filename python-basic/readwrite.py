#!/bin/python3

# months = open("months.txt")

# print(months.readlines())
# months.seek(0)
# print(months.readlines())

# for m in months:
#     # print(m)
#     print(m.strip())
# months.close()

# days = open("days.txt", "w")

# days.write("Monday")

# days.close()

days = open("days.txt", "a") # a - append

days.write("\nTuesday")

days.close()