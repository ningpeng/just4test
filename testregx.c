#include <stdio.h>
#include <regex.h>
#include <assert.h>

//代码1：email格式检测
int test1() {
    //分配一个regex_t
    regex_t reg; 
    //编译（使用POSIX扩展模式、并忽略大小写），确认编译成功（返回0）
    assert(regcomp(&reg, "^[a-z0-9_]+@([a-z0-9-]+\\.)+[a-z0-9]+$", REG_EXTENDED | REG_ICASE) == 0);
    int ret = regexec(&reg, "steve@rim.jobs", 0, NULL, 0); //执行搜索
    //看看返回值：0表示匹配成功，1表示REG_NOMATCH
    printf("ret = %d, nomatch = %d\n", ret, REG_NOMATCH); 
    regfree(&reg); //记得释放空间
}

//代码2：匹配xml的tag，取出key/value
int test2() {
    const char *str = "<key>value</key>";
    regex_t reg;
        int i, j ;

    assert(regcomp(&reg, "<([^>]*)>([^<]*)</\\1>", REG_EXTENDED) == 0); //编译
    const int nr_match = 3;  //串本身 + 2个子匹配
    regmatch_t matches[nr_match]; //存储匹配的起始位置和结束位置
    int ret = regexec(&reg, str, nr_match, matches, 0);
    if (ret == 0) { //匹配成功
        for ( i = 0; i < nr_match; i++) { //先输出整个串，再依次输出子匹配
            for ( j = matches[i].rm_so; j < matches[i].rm_eo; j++) // [起始, 结束)
                putchar(str[j]);
            putchar('\n');
        }
    }
    else if (ret == REG_NOMATCH) { //匹配失败
        printf("no match\n");
    }
    else { //执行错误
        char msgbuf[256];
        regerror(ret, &reg, msgbuf, sizeof(msgbuf)); //输出错误信息至字符数组
        printf("error: %s\n", msgbuf);
    }
    regfree(&reg);
    return 0;
}


//代码3：找出所有匹配的字符串（regexec只匹配第一个）
int test3() {
    regex_t reg;
    const char *str = "<k1>v1</k1><k2>v2</k2><k3>v3</k3>";
    assert(regcomp(&reg, "<([^>]*)>([^<]*)</\\1>", REG_EXTENDED) == 0); 
    const int nr_match = 3;
    regmatch_t matches[nr_match];
        int i, j;

    const char *start = str;
    while (1) {
        int ret = regexec(&reg, start, nr_match, matches, 0); 
        if (ret == 0)
        {  
            for ( i = 0; i < nr_match; i++)
            {  
                for ( j = matches[i].rm_so; j < matches[i].rm_eo; j++)
                    putchar(start[j]);
                putchar('\n');
            }  
            start += matches[0].rm_eo;  //下次从 这次匹配末尾 开始搜索
            continue; 
        }  
        if (ret == REG_NOMATCH)
            printf("no match\n");
        else {
            char msgbuf[256];
            regerror(ret, &reg, msgbuf, sizeof(msgbuf));
            printf("error: %s\n", msgbuf);
        }  
        break;
    }
    regfree(&reg);
    return 0;
}

int main()
{
        test1();
        test2();
        test3();
}

