import time

# Decorator to measure execution time
def timeit(f):

    # Decorator's wrapper function
    def timed(*args, **kwargs):

        start_time = time.time()
        result = f(*args, **kwargs)
        end_time = time.time()

        time_elapsed = round(end_time - start_time, 2)

        print(f'func: {f.__name__} took {time_elapsed}sec to complete.')
        return result
    
    return timed