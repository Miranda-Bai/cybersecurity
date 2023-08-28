#!/bin/python3

from Employees import Employees

e1 = Employees("Bob", "Sales", "Director of sales", 100000, 20)
e2 = Employees("Linda", "Executive", "CIO", 200000, 12)

print(e1.department)
print(e2.eligible_of_retirement())