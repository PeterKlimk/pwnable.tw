target = 7174
prices = [199, 299, 399, 499]

current = set([target])
ways = {target: []}

while True:
    new = set()
    for num in current:
        for price in prices:
            result = num - price
            if result not in ways:
                ways[result] = ways[num] + [price]

            if result == 0:
                print(sorted(ways[0]))
                exit()

            elif result > 0:
                new.add(result)

    current = new