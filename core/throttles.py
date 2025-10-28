from rest_framework.throttling import UserRateThrottle

class loginThrottle(UserRateThrottle):
    rate = '5/min'  # Limit to 5 login attempts per minute

