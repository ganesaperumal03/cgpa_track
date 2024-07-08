from datetime import datetime

current_year = datetime.now().year
batch_years = [f'{year}-{year + 4}' for year in range(current_year - 4, current_year + 1)]
print(batch_years)