#!/usr/bin/env python3
"""
identity.py — shared identity layer for the SDGpy and ESQL-DataFederation
generators.

Everything here is a PURE FUNCTION OF A KEY (employee id, IP address, account
id), computed with keyed SHA-256 hashing rather than sequential seeded draws.
Any generator, in any repo, run in any order, therefore computes the same
person for the same key. No lookup files, no import-order coupling, no seed
drift: insert a new field into one generator and nothing shifts anywhere else.

The module defines:

  EMPLOYEES      20,025 identities, employee ids 1..20025, rendered as
                 7-digit strings with a guaranteed leading zero ("0000356").
                 Each employee owns exactly one IP inside 10.49.0.0/17 and
                 one bank account inside the employee account band.

  CLIENT IPs     10.49.0.0/17 (10.49.0.1 .. 10.49.127.254). Employee IPs are
                 a hash-selected permutation of that space; the remaining
                 addresses are unassigned (DHCP churn, printers, ...).
                 SUSPICIOUS_IP is pinned to a real employee so the HR roster
                 does not give the game away.

  ACCOUNTS       1 .. TOTAL_ACCOUNTS (50,000,000). Holder type (individual /
                 corporation / government / union) is a deterministic function
                 of the account id. Employees hold the band
                 EMPLOYEE_ACCOUNT_BASE+1 .. EMPLOYEE_ACCOUNT_BASE+20025.

  FRAUD HOOKS    SEC_FRAUD_EMP_ID    an employee in Finance > Stock_Administration
                                     whose brokerage history shows a repeating
                                     buy-thin-stock / sell-into-spike pattern.
                 GOV_SUSPECT_ACCOUNT a county government account with
                                     structured, off-hours cash withdrawals.

Consumers load this file from the same directory (the gen_parquet_orders
importlib pattern) and should assert on IDENTITY_VERSION.
"""

import hashlib
import ipaddress
from datetime import date, timedelta

IDENTITY_VERSION = "1"

# ---------------------------------------------------------------------------
# Core keyed hash
# ---------------------------------------------------------------------------

def _h(namespace: str, key) -> int:
    """Stable 64-bit hash of (namespace, key). The only source of randomness."""
    digest = hashlib.sha256(f"{namespace}:{key}".encode()).digest()
    return int.from_bytes(digest[:8], "big")


def _wpick(namespace: str, key, pairs):
    """Deterministic weighted pick from [(label, weight), ...]."""
    total = sum(w for _, w in pairs)
    n = _h(namespace, key) % (total * 1000)
    acc = 0
    for label, w in pairs:
        acc += w * 1000
        if n < acc:
            return label
    return pairs[-1][0]


# ---------------------------------------------------------------------------
# Employees
# ---------------------------------------------------------------------------

NUM_EMPLOYEES = 20_025

HIRE_START = date(2012, 3, 15)
HIRE_END = date(2026, 3, 15)
_HIRE_SPAN = (HIRE_END - HIRE_START).days

# The employee whose brokerage history carries the securities-fraud pattern.
# Department/Team are forced to Finance > Stock_Administration below.
SEC_FRAUD_EMP_ID = 11_209                      # "0011209"

# Departments and teams. Weights follow the original HR brief; the Team
# column replaces the old Sub-Department column. Stock_Administration is new
# and exists so the securities-fraud employee sits somewhere plausible.
DEPARTMENTS = [
    ("Sales", 35),
    ("Engineering", 20),
    ("Marketing", 15),
    ("Support", 16),
    ("Finance", 9),
    ("Legal", 4),
    ("Leadership", 1),
]

_AE = _SA = _SDR = 100.0
TEAMS = {
    "Sales": [
        ("Account_Executive", _AE),
        ("Solution_Architect", _SA),
        ("SDR", _SDR),
        ("AE_Manager", _AE * 0.05),
        ("SA_Manager", _SA * 0.05),
        ("SDR_Manager", _SDR * 0.03),
    ],
    "Engineering": [("Engineer", 85), ("Product_Manager", 10), ("Director", 5)],
    "Marketing": [("Webinars", 1), ("Trade_Shows", 1), ("Commercials", 1)],
    "Support": [("Support_Engineer", 80), ("Escalation_Manager", 15),
                ("Support_Manager", 5)],
    "Finance": [("Order_Ops", 1), ("Comptroller", 1),
                ("Commission_Management", 1), ("Stock_Administration", 1)],
    "Legal": [("Compliance", 1), ("Vendor_Relations", 1),
              ("Customer_Relations", 1)],
    "Leadership": [("Executive", 40), ("Chief_Of_Staff", 25),
                   ("Board_Relations", 20), ("Corp_Dev", 15)],
}

# ---------------------------------------------------------------------------
# Name pools (promoted from gen_hr_csv.py — the canonical lists)
# ---------------------------------------------------------------------------

FIRST_NAMES = [
    "Aaron", "Abigail", "Adam", "Adrian", "Aisha", "Alan", "Alejandro", "Alex",
    "Alice", "Amara", "Amelia", "Amir", "Ana", "Andre", "Andrea", "Angela",
    "Anika", "Anna", "Anthony", "Anya", "Ariana", "Arjun", "Ashley", "Aubrey",
    "Austin", "Ava", "Avery", "Ayesha", "Beatriz", "Benjamin", "Bianca",
    "Blake", "Bogdan", "Brandon", "Brenda", "Brian", "Bridget", "Brooke",
    "Caleb", "Camila", "Carlos", "Carmen", "Caroline", "Casey", "Catherine",
    "Cecilia", "Chandra", "Charles", "Charlotte", "Chen", "Chloe", "Chris",
    "Claire", "Clara", "Cole", "Colin", "Connor", "Cora", "Craig", "Cynthia",
    "Damian", "Daniel", "Daphne", "Darius", "David", "Deepak", "Delia",
    "Denise", "Derek", "Devon", "Diana", "Diego", "Dmitri", "Dominic",
    "Dorothy", "Douglas", "Duncan", "Edward", "Eileen", "Elena", "Eli",
    "Elijah", "Elise", "Emeka", "Emily", "Emma", "Eric", "Erin", "Esther",
    "Ethan", "Eva", "Evelyn", "Ezra", "Farah", "Felix", "Fiona", "Frank",
    "Freya", "Gabriel", "Gabriela", "Gavin", "Genevieve", "George", "Grace",
    "Graham", "Gregory", "Gulhan", "Hana", "Hannah", "Harold", "Harper",
    "Hassan", "Hazel", "Heather", "Hector", "Helen", "Henry", "Hugo", "Ian",
    "Ibrahim", "Idris", "Ilya", "Imani", "Ingrid", "Irene", "Isaac", "Isabel",
    "Ivan", "Jack", "Jacob", "Jade", "Jae", "James", "Jamie", "Jasmine",
    "Jason", "Javier", "Jean", "Jenna", "Jeremy", "Jessica", "Jian", "Joan",
    "Joel", "John", "Jonas", "Jordan", "Jose", "Joshua", "Julia", "Julian",
    "Justin", "Kai", "Kaitlyn", "Karen", "Katrina", "Keiko", "Keith", "Kenji",
    "Kevin", "Khalid", "Kiara", "Kim", "Kwame", "Kyle", "Lars", "Laura",
    "Lauren", "Leah", "Lena", "Leo", "Leon", "Leticia", "Levi", "Liam",
    "Lila", "Lillian", "Linda", "Logan", "Lorenzo", "Lucas", "Lucia", "Luis",
    "Luka", "Lydia", "Maddox", "Maria", "Mariam", "Marcus", "Margaret",
    "Marta", "Martin", "Mason", "Mateo", "Matthew", "Maya", "Megan", "Mei",
    "Melanie", "Micah", "Michael", "Michelle", "Miguel", "Mila", "Miles",
    "Miranda", "Mohammed", "Molly", "Nadia", "Naomi", "Natalie", "Nathan",
    "Nia", "Nicholas", "Nicole", "Nina", "Noah", "Noor", "Nora", "Olga",
    "Olivia", "Omar", "Oscar", "Owen", "Pablo", "Paige", "Patrick", "Paul",
    "Paula", "Pedro", "Peter", "Philip", "Pia", "Priya", "Quinn", "Rachel",
    "Rafael", "Rahul", "Raj", "Ramona", "Randall", "Raquel", "Ravi", "Rebecca",
    "Reza", "Rhea", "Ricardo", "Richard", "Riley", "Rita", "Robert", "Rosa",
    "Rowan", "Ruben", "Ruth", "Ryan", "Sabrina", "Sadie", "Salma", "Samuel",
    "Sandra", "Sanjay", "Sara", "Sasha", "Scott", "Sean", "Selena", "Serena",
    "Seth", "Shane", "Shannon", "Shawn", "Sheila", "Shen", "Sienna", "Silas",
    "Simone", "Sofia", "Sonia", "Sophia", "Stefan", "Stella", "Stephanie",
    "Stuart", "Sung", "Susan", "Sven", "Sylvia", "Tara", "Tessa", "Theo",
    "Theresa", "Thomas", "Tiffany", "Timothy", "Tobias", "Tomas", "Tracy",
    "Trevor", "Tyler", "Uma", "Valentina", "Vanessa", "Vera", "Veronica",
    "Victor", "Viktor", "Vincent", "Violet", "Vivian", "Walter", "Wendy",
    "Wesley", "Whitney", "Wei", "William", "Willow", "Xavier", "Ximena",
    "Yara", "Yasmin", "Yolanda", "Yusuf", "Zachary", "Zara", "Zoe",
]

LAST_NAMES = [
    "Abbott", "Acosta", "Adams", "Aguilar", "Ahmed", "Akhtar", "Albright",
    "Almeida", "Alvarez", "Andersen", "Anderson", "Andrade", "Ansari",
    "Arellano", "Armstrong", "Ashford", "Atkinson", "Avila", "Bailey", "Baker",
    "Banerjee", "Barnes", "Barrett", "Bautista", "Beck", "Bennett", "Berg",
    "Bergstrom", "Bianchi", "Blackwell", "Blake", "Bogdanov", "Bonner",
    "Booth", "Bourne", "Bowman", "Boyd", "Bradley", "Brandt", "Brennan",
    "Bright", "Brooks", "Brown", "Bryant", "Burke", "Burton", "Bush", "Byrne",
    "Calderon", "Calloway", "Campbell", "Cantu", "Cardenas", "Carlisle",
    "Carpenter", "Carrillo", "Carter", "Castillo", "Cavanaugh", "Chan",
    "Chandler", "Chang", "Chavez", "Chen", "Cho", "Choi", "Christensen",
    "Clark", "Clinton", "Cohen", "Coleman", "Collins", "Conner", "Contreras", "Cooper",
    "Cortez", "Costa", "Cruz", "Cunningham", "Cupp", "Dalton", "Daniels", "Davenport",
    "Davis", "Delacruz", "Delgado", "Deshpande", "Diaz", "Dixon", "Dominguez",
    "Donnelly", "Dorsey", "Douglas", "Doyle", "Duarte", "Dubois", "Duffy",
    "Duncan", "Dunn", "Eaton", "Edwards", "Elliott", "Ellis", "Engel",
    "Espinoza", "Estrada", "Evans", "Farrell", "Faulkner", "Fernandez",
    "Ferreira", "Figueroa", "Finley", "Fischer", "Fitzgerald", "Fleming",
    "Fletcher", "Flores", "Flynn", "Ford", "Foster", "Fowler", "Franklin",
    "Freeman", "Fuentes", "Fujita", "Gallagher", "Gallo", "Garcia", "Gardner",
    "Garrett", "Gates", "George", "Gibson", "Gill", "Gilmore", "Glover",
    "Goldberg", "Gomez", "Gonzalez", "Goodwin", "Graham", "Grant", "Graves",
    "Gray", "Greene", "Griffin", "Guerrero", "Gupta", "Gutierrez", "Guzman",
    "Haddad", "Hale", "Hall", "Hamilton", "Hansen", "Harper", "Harrington",
    "Harris", "Hart", "Hartley", "Hassan", "Hayes", "Haynes", "Heath",
    "Henderson", "Hendricks", "Henry", "Hernandez", "Herrera", "Hicks",
    "Higgins", "Hill", "Hoffman", "Holland", "Holloway", "Holmes", "Hopkins",
    "Horton", "Howard", "Hudson", "Huerta", "Hughes", "Hunt", "Hunter",
    "Ibarra", "Ibrahim", "Iqbal", "Irwin", "Ishikawa", "Jackson", "Jacobs",
    "Jain", "James", "Jenkins", "Jensen", "Jimenez", "Johnson", "Jones",
    "Jordan", "Joseph", "Joshi", "Kaminski", "Kane", "Kaplan", "Katz",
    "Kaur", "Keller", "Kelly", "Kemp", "Kennedy", "Khan", "Kim", "King",
    "Kirby", "Klein", "Knight", "Kobayashi", "Koch", "Kowalski", "Kozlov",
    "Kramer", "Krause", "Kumar", "Lam", "Lambert", "Lane", "Lang", "Larsen",
    "Lawson", "Le", "Leach", "Lee", "Leon", "Leonard", "Levine", "Lewis",
    "Li", "Lindqvist", "Lindsey", "Little", "Liu", "Lloyd", "Logan", "Lopez",
    "Lowe", "Lucas", "Luna", "Lynch", "Ma", "Macdonald", "Mack", "Madsen",
    "Maher", "Malik", "Mallory", "Mancini", "Mann", "Manning", "Marder", "Marin",
    "Marsh", "Marshall", "Martin", "Martinez", "Marzette", "Mason", "Massey", "Mathews",
    "Matsuda", "Maxwell", "May", "Mayer", "Mccarthy", "McDermott", "Mcdonald", "Mcgrath",
    "Mckinney", "Medina", "Mehta", "Mejia", "Mendez", "Mendoza", "Mercer",
    "Meyer", "Miles", "Miller", "Mills", "Mitchell", "Moeller", "Molina",
    "Monroe", "Montgomery", "Moore", "Morales", "Moreau", "Moreno", "Morgan",
    "Morris", "Morrison", "Moss", "Mueller", "Mullins", "Munoz", "Murdoch",  "Murphy",
    "Murray", "Nakagawa", "Nakamura", "Navarro", "Nelson", "Newman", "Nguyen",
    "Nichols", "Nielsen", "Nixon", "Noble", "Nolan", "Norris", "Novak", "Obama",
    "Obrien", "Ochoa", "Odonnell", "Okafor", "Oliveira", "Olsen", "Olson",
    "Ortega", "Ortiz", "Osborne", "Owens", "Ozturk", "Pace", "Padilla",
    "Page", "Palmer", "Park", "Parker", "Parsons", "Patel", "Patterson",
    "Payne", "Pearson", "Pena", "Perez", "Perkins", "Perry", "Peters",
    "Petersen", "Petrov", "Phillips", "Pierce", "Pineda", "Polat", "Pollard",
    "Ponce", "Poole", "Pope", "Porter", "Powell", "Powers", "Prasad",
    "Preston", "Price", "Quinn", "Quintana", "Rahman", "Ramirez", "Ramos",
    "Ramsey", "Randall", "Rasmussen", "Reddy", "Reed", "Reese", "Reeves",
    "Reid", "Reilly", "Reyes", "Reynolds", "Rhodes", "Rice", "Richards",
    "Richardson", "Riley", "Rivas", "Rivera", "Roberts", "Robertson",
    "Robinson", "Rocha", "Rodgers", "Rodriguez", "Rogers", "Rojas", "Roman",
    "Romero", "Rosales", "Rose", "Ross", "Rossi", "Roth", "Rowe", "Ruiz",
    "Russell", "Ryan", "Salazar", "Salinas", "Sanchez", "Sanders", "Sandoval",
    "Santana", "Santiago", "Santos", "Sato", "Saunders", "Sawyer", "Schmidt",
    "Schneider", "Schroeder", "Schultz", "Schwartz", "Scott", "Serrano",
    "Shah", "Shaw", "Shelton", "Shepherd", "Sherman", "Shields", "Short",
    "Sidorov", "Silva", "Simmons", "Simon", "Sims", "Singh", "Slater",
    "Sloan", "Small", "Smith", "Snyder", "Sokolov", "Solis", "Solomon",
    "Song", "Soto", "Spencer", "Stafford", "Stanley", "Stark", "Steele",
    "Stein", "Stephens", "Stevens", "Stewart", "Stokes", "Stone", "Strickland",
    "Suarez", "Sullivan", "Summers", "Sutton", "Suzuki", "Swanson", "Sweeney",
    "Tanaka", "Tate", "Taylor", "Terry", "Thomas", "Thompson", "Thornton",
    "Tian", "Titov", "Tocci", "Todd", "Torres", "Tran", "Travis", "Trujillo", "Trump", "Tucker",
    "Turner", "Underwood", "Valdez", "Valencia", "Vance", "Vargas", "Vaughn",
    "Vazquez", "Vega", "Velazquez", "Villanueva", "Vincent", "Vogel", "Wade",
    "Wagner", "Walker", "Wallace", "Walsh", "Walton", "Wang", "Ward", "Ware",
    "Warner", "Warren", "Washington", "Waters", "Watkins", "Watson", "Weaver",
    "Webb", "Weber", "Webster", "Weiss", "Welch", "Wells", "West", "Wheeler",
    "Whitaker", "White", "Whitfield", "Wilcox", "Wilkins", "Williams",
    "Willis", "Wilson", "Winters", "Wise", "Wolfe", "Wong", "Wood", "Woods",
    "Wright", "Wu", "Xu", "Yamamoto", "Yang", "Yates", "Yildiz", "Yoon",
    "Young", "Yousef", "Zamora", "Zhang", "Zhao", "Zhou", "Zimmerman",
]

# ---------------------------------------------------------------------------
# Client IP space: 10.49.0.0/17
# ---------------------------------------------------------------------------

CLIENT_NET = ipaddress.IPv4Network("10.49.0.0/17")
_NET_INT = int(CLIENT_NET.network_address)
_NUM_HOSTS = CLIENT_NET.num_addresses - 2          # skip .0.0 and .127.255

# The credential-stuffing / enumeration actor in the application logs. Inside
# the /17, and pinned below to a real employee so the roster stays innocent.
SUSPICIOUS_IP = "10.49.110.17"

_EMP_IP = None            # employee id (1-based) -> ip string
_IP_EMP = None            # ip string -> employee id


def _build_ip_assignment():
    """Deterministic permutation of the /17 host space; first NUM_EMPLOYEES
    offsets become employee IPs. SUSPICIOUS_IP is swapped in if the
    permutation did not already select it."""
    global _EMP_IP, _IP_EMP
    if _EMP_IP is not None:
        return
    offsets = sorted(range(1, _NUM_HOSTS + 1), key=lambda o: _h("ip-perm", o))
    chosen = offsets[:NUM_EMPLOYEES]
    susp_off = int(ipaddress.IPv4Address(SUSPICIOUS_IP)) - _NET_INT
    if susp_off not in set(chosen):
        # replace a deterministic victim slot with the suspicious address
        chosen[_h("susp-slot", SUSPICIOUS_IP) % NUM_EMPLOYEES] = susp_off
    _EMP_IP = {}
    _IP_EMP = {}
    for emp, off in enumerate(chosen, start=1):
        ip = str(ipaddress.IPv4Address(_NET_INT + off))
        _EMP_IP[emp] = ip
        _IP_EMP[ip] = emp


# ---------------------------------------------------------------------------
# Employee API
# ---------------------------------------------------------------------------

def employee_id_str(emp: int) -> str:
    """7-digit employee id with a guaranteed leading zero: 356 -> '0000356'."""
    if not 1 <= emp <= NUM_EMPLOYEES:
        raise ValueError(f"employee id out of range: {emp}")
    return f"{emp:07d}"


def employee_ip(emp: int) -> str:
    _build_ip_assignment()
    return _EMP_IP[emp]


def employee_for_ip(ip: str):
    """Employee id owning this IP, or None if the address is unassigned."""
    _build_ip_assignment()
    return _IP_EMP.get(ip)


def employee(emp: int) -> dict:
    """The full identity record for one employee. Pure function of emp."""
    n = _h("employee", emp)
    first = FIRST_NAMES[n % len(FIRST_NAMES)]
    last = LAST_NAMES[(n >> 16) % len(LAST_NAMES)]
    if emp == SEC_FRAUD_EMP_ID:
        dept, team = "Finance", "Stock_Administration"
    else:
        dept = _wpick("dept", emp, DEPARTMENTS)
        team = _wpick("team", emp, TEAMS[dept])
    start = HIRE_START + timedelta(days=_h("hire", emp) % (_HIRE_SPAN + 1))
    return {
        "employee_id": employee_id_str(emp),
        "first_name": first,
        "last_name": last,
        "department": dept,
        "team": team,
        "start_date": start.strftime("%Y-%m-%d"),
        "ip": employee_ip(emp),
        "username": username(first, last),
    }


def username(first: str, last: str) -> str:
    """jmartinez-style login derived from the roster name."""
    return (first[0] + last).lower().replace(" ", "").replace("'", "")


def client_pool(size: int = 900):
    """A stable subset of employee IPs for log baselines: the `size` employees
    with the smallest hash win, forever, regardless of anything else."""
    emps = sorted(range(1, NUM_EMPLOYEES + 1),
                  key=lambda e: _h("client-pool", e))[:size]
    return [employee_ip(e) for e in emps]


def chatty_clients(pool, count: int = 25):
    """High-volume legitimate clients, chosen deterministically from a pool."""
    return sorted(pool, key=lambda ip: _h("chatty", ip))[:count]


# ---------------------------------------------------------------------------
# Accounts: 1 .. 50,000,000
# ---------------------------------------------------------------------------

TOTAL_ACCOUNTS = 50_000_000
EMPLOYEE_ACCOUNT_BASE = 49_000_000            # employees hold BASE+1..BASE+20025

SEC_FRAUD_ACCOUNT = EMPLOYEE_ACCOUNT_BASE + SEC_FRAUD_EMP_ID

# County government account with structured, off-hours cash withdrawals.
GOV_SUSPECT_ACCOUNT = 23_114_007

CORP_SECTORS = [
    ("technology", 16), ("retail", 15), ("healthcare", 12),
    ("construction", 11), ("logistics", 10), ("energy", 9),
    ("hospitality", 9), ("agriculture", 7), ("real_estate", 6),
    ("professional_services", 5),
]

GOV_LEVELS = [("county", 60), ("state", 30), ("federal", 10)]

UNION_TYPES = [
    ("teacher", 16), ("police", 12), ("fire_fighter", 10),
    ("steel_worker", 9), ("railroad", 8), ("emt", 7),
    ("nurses_doctors", 12),
    ("manufacturing_automotive", 9), ("manufacturing_aviation", 6),
    ("manufacturing_electronics", 5), ("manufacturing_shipbuilding", 3),
    ("manufacturing_heavy_equipment", 3),
]


def is_employee_account(acct: int) -> bool:
    return EMPLOYEE_ACCOUNT_BASE < acct <= EMPLOYEE_ACCOUNT_BASE + NUM_EMPLOYEES


def employee_for_account(acct: int):
    """Employee id for an employee-band account, else None."""
    return acct - EMPLOYEE_ACCOUNT_BASE if is_employee_account(acct) else None


def employee_account(emp: int) -> int:
    return EMPLOYEE_ACCOUNT_BASE + emp


def account_holder(acct: int):
    """(holder_type, holder_subtype, employee_id-or-None) for any account.
    Deterministic; the fraud hooks are forced so they land where the
    narrative needs them."""
    emp = employee_for_account(acct)
    if emp is not None:
        return "individual", "employee", employee_id_str(emp)
    if acct == GOV_SUSPECT_ACCOUNT:
        return "government", "county", None
    n = _h("holder", acct) % 10_000
    if n < 9_690:
        return "individual", "retail", None
    if n < 9_910:
        return "corporation", _wpick("corp", acct, CORP_SECTORS), None
    if n < 9_945:
        return "government", _wpick("gov", acct, GOV_LEVELS), None
    return "union", _wpick("union", acct, UNION_TYPES), None
