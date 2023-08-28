#!/bin/python3

from Shoes import Shoes

low = Shoes("And 1s", 30)
medium = Shoes("Air Force 1s", 120)
high= Shoes("Off Whites", 400)

try:
    shoe_budget = float(input("What's your shoe budget? "))
except ValueError:
    exit("Please enter a number!")

for shoes in [high, medium, low]:
    shoes.buy(shoe_budget)