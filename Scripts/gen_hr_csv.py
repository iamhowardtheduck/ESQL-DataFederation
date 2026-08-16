#!/usr/bin/env python3
"""
gen_hr_csv.py — HR roster keyed to the client IP range, one row per IP.

Emits one employee per address in 10.30.255.0 .. 10.50.255.0 (1,310,721 rows),
so parsed clientIp values from the application logs can be joined straight to a
person, department, and tenure.

Columns:
    IP_Address, First_Name, Last_Name, Department, Sub-Department, Start_Date

Department mix:
    sales 35%, engineering 20%, marketing 15%, support 15%,
    finance 8%, legal 4%, leadership 3%

Sub-department mix:
    legal        compliance / vendor-relations / customer-relations (even)
    finance      order-ops / comptroller / commission-management (even)
    marketing    webinars / trade-shows / commercials (even)
    sales        account_executive, solution_architect, sdr weighted evenly as
                 the IC base; ae_manager = 5% of AE, sa_manager = 5% of SA,
                 sdr_manager = 3% of SDR
    support      support_engineer 80 / escalation_manager 15 / support_manager 5
    engineering  engineer 85 / product_manager 10 / director 5
    leadership   executive / chief_of_staff / board_relations / corp_dev
                 (not specified in the brief -- adjust LEADERSHIP_SUBS to taste)

Start_Date is uniform over 2012-03-15 .. 2026-03-15, formatted YYYY-MM-DD.

Usage:
    python3 gen_hr_csv.py
    python3 gen_hr_csv.py --out hr_roster.csv
    python3 gen_hr_csv.py --limit 5000            # small sample for testing
    python3 gen_hr_csv.py --parquet hr_roster.parquet
"""
import argparse
import csv
import ipaddress
import os
import random
from datetime import date, timedelta

START_IP = "10.30.255.0"
END_IP = "10.50.255.0"

HIRE_START = date(2012, 3, 15)
HIRE_END = date(2026, 3, 15)

# Address that behaves maliciously in the application logs. Included here like
# any other employee -- the roster must not give the game away.
SUSPICIOUS_IP = "10.49.110.17"

# ---------------------------------------------------------------------------
# Department weights (percent, must total 100)
# ---------------------------------------------------------------------------
DEPARTMENTS = [
    ("sales", 35),
    ("engineering", 20),
    ("marketing", 15),
    ("support", 15),
    ("finance", 8),
    ("legal", 4),
    ("leadership", 3),
]

# ---------------------------------------------------------------------------
# Sub-department weights, per department
# ---------------------------------------------------------------------------
# sales: the brief pins each manager role to its IC role but not the ICs to
# each other, so the three IC tracks are weighted evenly as the base.
_AE = _SA = _SDR = 100.0
SALES_SUBS = [
    ("account_executive", _AE),
    ("solution_architect", _SA),
    ("sdr", _SDR),
    ("ae_manager", _AE * 0.05),
    ("sa_manager", _SA * 0.05),
    ("sdr_manager", _SDR * 0.03),
]

LEADERSHIP_SUBS = [
    ("executive", 40),
    ("chief_of_staff", 25),
    ("board_relations", 20),
    ("corp_dev", 15),
]

SUB_DEPARTMENTS = {
    "legal": [("compliance", 1), ("vendor-relations", 1), ("customer-relations", 1)],
    "finance": [("order-ops", 1), ("comptroller", 1), ("commission-management", 1)],
    "marketing": [("webinars", 1), ("trade-shows", 1), ("commercials", 1)],
    "sales": SALES_SUBS,
    "support": [("support_engineer", 80), ("escalation_manager", 15),
                ("support_manager", 5)],
    "engineering": [("engineer", 85), ("product_manager", 10), ("director", 5)],
    "leadership": LEADERSHIP_SUBS,
}

# ---------------------------------------------------------------------------
# Name pools
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
    "Bright", "Brooks", "Brown", "Bryant", "Burke", "Burton", "Byrne",
    "Calderon", "Calloway", "Campbell", "Cantu", "Cardenas", "Carlisle",
    "Carpenter", "Carrillo", "Carter", "Castillo", "Cavanaugh", "Chan",
    "Chandler", "Chang", "Chavez", "Chen", "Cho", "Choi", "Christensen",
    "Clark", "Cohen", "Coleman", "Collins", "Conner", "Contreras", "Cooper",
    "Cortez", "Costa", "Cruz", "Cunningham", "Dalton", "Daniels", "Davenport",
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
    "Maher", "Malik", "Mallory", "Mancini", "Mann", "Manning", "Marin",
    "Marsh", "Marshall", "Martin", "Martinez", "Mason", "Massey", "Mathews",
    "Matsuda", "Maxwell", "May", "Mayer", "Mccarthy", "Mcdonald", "Mcgrath",
    "Mckinney", "Medina", "Mehta", "Mejia", "Mendez", "Mendoza", "Mercer",
    "Meyer", "Miles", "Miller", "Mills", "Mitchell", "Moeller", "Molina",
    "Monroe", "Montgomery", "Moore", "Morales", "Moreau", "Moreno", "Morgan",
    "Morris", "Morrison", "Moss", "Mueller", "Mullins", "Munoz", "Murphy",
    "Murray", "Nakagawa", "Nakamura", "Navarro", "Nelson", "Newman", "Nguyen",
    "Nichols", "Nielsen", "Nixon", "Noble", "Nolan", "Norris", "Novak",
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
    "Tian", "Todd", "Torres", "Tran", "Travis", "Trujillo", "Tucker",
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


def weighted_pool(pairs):
    """Return (labels, weights) split from a list of (label, weight) tuples."""
    return [p[0] for p in pairs], [p[1] for p in pairs]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="hr_roster.csv")
    ap.add_argument("--start-ip", default=START_IP)
    ap.add_argument("--end-ip", default=END_IP)
    ap.add_argument("--limit", type=int, default=0,
                    help="stop after N rows (0 = full range)")
    ap.add_argument("--parquet", default=None,
                    help="also write a Parquet copy to this path")
    ap.add_argument("--seed", type=int, default=1337)
    args = ap.parse_args()

    random.seed(args.seed)

    lo = int(ipaddress.IPv4Address(args.start_ip))
    hi = int(ipaddress.IPv4Address(args.end_ip))
    if hi < lo:
        raise SystemExit("--end-ip must be >= --start-ip")
    total = hi - lo + 1
    if args.limit:
        total = min(total, args.limit)

    dept_labels, dept_weights = weighted_pool(DEPARTMENTS)
    sub_pools = {d: weighted_pool(SUB_DEPARTMENTS[d]) for d in dept_labels}

    span_days = (HIRE_END - HIRE_START).days

    rows = []
    dept_counts = {d: 0 for d in dept_labels}
    sub_counts = {}

    for offset in range(total):
        addr = str(ipaddress.IPv4Address(lo + offset))
        dept = random.choices(dept_labels, weights=dept_weights, k=1)[0]
        labels, weights = sub_pools[dept]
        sub = random.choices(labels, weights=weights, k=1)[0]
        start = HIRE_START + timedelta(days=random.randrange(span_days + 1))

        dept_counts[dept] += 1
        sub_counts[(dept, sub)] = sub_counts.get((dept, sub), 0) + 1

        rows.append((
            addr,
            random.choice(FIRST_NAMES),
            random.choice(LAST_NAMES),
            dept,
            sub,
            start.strftime("%Y-%m-%d"),
        ))

    header = ["IP_Address", "First_Name", "Last_Name", "Department",
              "Sub-Department", "Start_Date"]

    with open(args.out, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(header)
        w.writerows(rows)

    if args.parquet:
        import pyarrow as pa
        import pyarrow.parquet as pq
        cols = list(zip(*rows))
        table = pa.table({
            "IP_Address": pa.array(cols[0], pa.string()),
            "First_Name": pa.array(cols[1], pa.string()),
            "Last_Name": pa.array(cols[2], pa.string()),
            "Department": pa.array(cols[3], pa.string()),
            "Sub-Department": pa.array(cols[4], pa.string()),
            "Start_Date": pa.array(cols[5], pa.string()),
        })
        pq.write_table(table, args.parquet, compression="snappy",
                       row_group_size=100_000)

    # ---- summary -----------------------------------------------------------
    size = os.path.getsize(args.out) / 1e6
    print(f"wrote {args.out}: {len(rows):,} rows x {len(header)} cols ({size:.1f} MB)")
    print(f"  IP range   : {args.start_ip} .. "
          f"{ipaddress.IPv4Address(lo + total - 1)}")
    print(f"  Start_Date : {HIRE_START} .. {HIRE_END}")
    if args.parquet:
        print(f"  parquet    : {args.parquet} "
              f"({os.path.getsize(args.parquet) / 1e6:.1f} MB)")

    print("\n  Department distribution")
    for d in dept_labels:
        c = dept_counts[d]
        print(f"    {d:<12} {c:>9,}  {c / len(rows) * 100:5.2f}%")

    print("\n  Sub-department distribution (% within department)")
    for d in dept_labels:
        for label, _ in SUB_DEPARTMENTS[d]:
            c = sub_counts.get((d, label), 0)
            within = c / dept_counts[d] * 100 if dept_counts[d] else 0
            print(f"    {d:<12} {label:<22} {c:>8,}  {within:5.2f}%")


if __name__ == "__main__":
    main()
