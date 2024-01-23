import pandas as pd

# 합칠 파일의 개수 (맞춰서 수정)
num_files = 67

# 각 파일을 읽어 하나의 DataFrame으로 결합
df_list = [pd.read_csv(f'updated_domains_{i}.csv', encoding='utf-8') for i in range(num_files)]
combined_df = pd.concat(df_list, ignore_index=True)

# 'domain' 칼럼 제거
combined_df.drop('domain', axis=1, inplace=True)

# 'smishing' 칼럼 추가 (모든 값은 0)
combined_df['smishing'] = 0

# 결합된 DataFrame을 새로운 파일로 저장 (맞춰서 수정)
combined_df.to_csv('normal_url_1.csv', index=False, encoding='utf-8')
