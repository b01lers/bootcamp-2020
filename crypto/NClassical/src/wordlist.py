from string import ascii_letters
f = open('script.txt','r') #inception movie script 
text = [x.replace('\n','') for x in f.readlines()]

words = []
for phrases in text:
    phrases = phrases.split(' ')
    for x in phrases:
        var = True
        if x != '' and len(x) > 3:
            for char in x:
                if char not in ascii_letters:
                    var = False
            if var:
                words.append(x.lower())
        var = True
words = [set(words)]
print(f'words = {words}')
