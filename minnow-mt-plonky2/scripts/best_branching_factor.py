throughput = 100000
slot_length = 0.5
inputs_per_slot = throughput * slot_length
x = inputs_per_slot

batch_size = 100
y = batch_size

num_batches = x / y
if x % y != 0:
    print("x must be divisible by y")
    exit(0)

beta = num_batches
# TODO: Finish this