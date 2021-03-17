count=$1
>emails.csv
while (( count <= $2 ));do echo "test+$count@gmail.com" >> emails.csv; (( count++ )); done
