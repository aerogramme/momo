class UsersRegisteration(object):
    def __init__(self, firstname, lastname, email, phone, network, username, password, balance, debt):
        self.firstname = firstname
        self.lastname = lastname
        self.email = email
        self.phone = phone
        self.network = network
        self.username = username
        self.password = password
        self.balance = 0.0
        self.debt = 0.0

class TopUpMongo(object):
    def __init__(self, username, amount, network, phone):
        self.username = username
        self.amount  = amount
        self.network = network
        self.phone = phone

class CheckBalanceMongo(object):
    def __init__(self):
        pass

class TransferMongo(object):
    def __init__(self,username, amountBeforeFees, amountAfterFees, fromPhone, toPhone, toNetwork,fromNetwork):
        self.username = username
        self.amountBeforeFees = amountBeforeFees
        self.amountAfterFees = amountAfterFees
        self.fromPhone = fromPhone
        self.toPhone = toPhone
        self.toNetwork = toNetwork
        self.fromNetwork = fromNetwork
