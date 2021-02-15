import sympy
import numpy as np

def Indy2Vec(v1, v2):
    matrix = np.array([v1,v2])

    _, indexes = sympy.Matrix(matrix).T.rref()  # T is for transpose
    if len(indexes) == 2:
        return True
    else:
        return False

v1 = np.array([0, 5, 0])
v2 = np.array([0, -10, 0])
v3 = np.array([1, 2, 3])
v4 = np.array([-2, -4, -6])

assert Indy2Vec(v1, v2) == False, "Your code said that two linearly dependent vectors were independent"
assert Indy2Vec(v3, v4) == False, "Your code said that two linearly dependent vectors were independent"
assert Indy2Vec(v1, v3) == True, "Your code said that two linearly independent vectors were dependent"
assert Indy2Vec(v2, v3) == True, "Your code said that two linearly independent vectors were dependent"