python3 -m venv .venv
source .venv/bin/activate
pip install pandas numpy elasticsearch faker pyarrow 
cd /home/elastic/ESQL-DataFederation/Scripts && ./.venv/bin/python gen_parquet.py --rows 50000
mc alias set local http://localhost:9000 minioadmin 'datafederation_hooray!'
mc admin info local
mc mb local/datasets
mc cp --recursive transactions.parquet local/datasets/transactions/
mc ls -r local/datasets/
mc alias list
mc ls -r local/datasets/
cd /home/elastic/ESQL-DataFederation/Scripts
mc cp --recursive transactions_history/ local/datasets/transactions/
cd /home/elastic/ESQL-DataFederation/Scripts && .venv/bin/python gen_parquet_logs.py --rows 2000000 --days 30 --suspicious-rate 0.06
mc cp --recursive app_logs.parquet local/datasets/logs/
clear
echo ""
echo ""
echo "You are now ready to begin the assignment."
echo ""
echo ""
