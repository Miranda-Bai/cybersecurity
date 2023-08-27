#!/bin/python3

# print strings
print("Hello world!")
print("""This string runs
multiple lines!""")
print("This string is " + "awesome!")

# MATH
print(50 + 50)  # add
print(50 - 30)  # subtract
print(50 * 50)  # multiply
print(50 / 4)  # divide
print(50 ** 2)  # exponents
print(50 % 6)  # modulo - takes what is left over
print(50 / 6)  # division with remainder or a float
print(50 // 6)  # no remainder

# Variables and methods
quote = "The quieter you become, the more you will hear."
print(quote)
quote = "All is fair in love and war."
print(quote.upper())  # upper
print(quote.lower())  # lower
print(quote.title())  # title case, every first letter of each word
print(len(quote))  # counts characters including spaces

# Methods
age = 31
str1 = "1"
print(age + int(str1))

print("**\n")
# Functions
def testfun():
    print("who am I?")

testfun()

def who_am_i(name, age):
    print("I'm " + name + " and " + str(age) + " years old.")

who_am_i("M", 31)

def multiply(x, y):
    return x * y

print(multiply(3,4))

print(type(age))

# LISTS - Have brackets []
movies=["When Harry met Sally", "The Hangover", "The Perks of Being a Wallflower", "The Exorcist"]
print(movies[1:3]) # return the first index number given right until the last number, but not include the last number

print(movies[1:]) # ["The Hangover", 'The Perks of Being a Wallflower', 'The Exorcist']
print(movies[:1]) # ["When Harry met Sally"]
print(movies[-1]) # The Exorcist # return the last item in the list

print(len(movies)) # count items in the list

movies.append("JAWS")
print(movies)

movies.insert(2, "Hustle")
print(movies)

movies.pop() # remove the last item
print(movies)

movies.pop(0) # remove the first item
print(movies)

amber_movies = ["Just Go With It", "50 First Date"]
our_favorite_movies = movies + amber_movies
print(our_favorite_movies)

grade = [["Bob", 82], ["Alice", 90], ["Jeff", "male"]]

print(grade[2][1])

# Tuples - Do not change, ()
grades = ("a", "b", "c", "d", "f")
print(grades[3])

# For loop - start to finish of an iterate
for x in grades:
    print(x)

# While loop - execute as long as True
i = 1
while i < 10:
    print(i)
    i += 1

# Advanced strings

my_name = "Health"
print(my_name[0])
print(my_name[-1])

sentence = "This is a sentence."
print(sentence[:4])
print(sentence.split()) # delimeter - default is a space

sentence_split = sentence.split()
sentence_join = " ".join(sentence_split)
print(sentence_join)

quote="He said, 'give me all your money'."
print(quote)

quote = "He said, \"give me all your money\"."
print(quote)
