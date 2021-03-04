import pyautogui

import time
# time.sleep(3)
t=5
while t>0:
    x=pyautogui.locateCenterOnScreen("bartl.png")
    pyautogui.click(x)
