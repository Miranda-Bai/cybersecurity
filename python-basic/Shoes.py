class Shoes:
    def __init__(self, name, price) -> None:
        self.name = name
        self.price = price
    def budget_check(self, budget):
        if not isinstance(budget, (int, float)):
            print("Invalid entry. Please enter a number.")
            exit()
    
    def change(self, budget):
        return (budget - self.price)
    
    def buy(self, budget):
        self.budget_check(budget)
        if budget>= self.price:
            print(f"You can cop some {self.name}")

            if budget == self.price:
                print("You have exactly enough money for these shoes.")
            else:
                print(f"You can buy these shoes and have ${self.change(budget)} left over.")
            exit("Thanks for using our shoe budget app!")

        # print(f"You don't have enough budget for {self.name}.")
        