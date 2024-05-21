import os 

def split_file(input_file, lines_per_file, output_dir):
    # Tạo thư mục nếu chưa tồn tại
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    with open(input_file, 'r', encoding='utf-8') as file:
        lines = file.readlines()
    
    total_lines = len(lines)
    file_count = total_lines // lines_per_file + (1 if total_lines % lines_per_file != 0 else 0)
    print("Tổng số dòng: " + str(total_lines))

    for i in range(file_count):
        start_line = i * lines_per_file
        end_line = min(start_line + lines_per_file, total_lines)
        output_file = os.path.join(output_dir, f"{input_file.replace('.log', '')}_part{i+1}.log")
        
        with open(output_file, 'w', encoding='utf-8') as output:
            output.writelines(lines[start_line:end_line])

        print(f"Created {output_file} with lines from {start_line+1} to {end_line}")

# Usage
input_file = 'HDFS.log'
lines_per_file = 300000
output_dir = 'split_HDFS'
split_file(input_file, lines_per_file, output_dir)