#!/bin/bash

# 检查是否有参数传递
if [ "$#" -eq 0 ]; then
  echo "请提供至少一个程序名称作为参数。"
  exit 1
fi

# 循环执行每个参数
for program in "$@"
do
  echo "正在运行程序: $program"
  $program
  # 检查程序是否成功执行
  if [ $? -ne 0 ]; then
    echo "程序 $program 执行失败。"
  else
    echo "程序 $program 执行成功。"
  fi
done
