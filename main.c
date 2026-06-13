#include <gtk/gtk.h>
#include <arpa/inet.h>
#include "api.h"
#include "db.h"

typedef struct{
	GtkWidget *input;
	GtkWidget *output;
	GtkWidget *combo;
} EncodeWidgets;
typedef struct{
	GtkWidget *entry;
	GtkWidget *label;
} AppWidgets;
typedef struct{
    const char *name;
    char *(*fn)(const char *ip);
    GtkWidget *btn;
    GtkWidget *check;
    char *last_result;
    gboolean enabled;
} Checker;
typedef struct{
	const char *ip;
	int index;
} ThreadArg;
typedef struct{
	GtkWidget *label;
	char *text;

}LabelUpdate;
static gboolean update_label(gpointer data){
	LabelUpdate *u=(LabelUpdate *)data;
	gtk_label_set_text(GTK_LABEL(u->label),u->text);
	free(u->text);
	free(u);
	return G_SOURCE_REMOVE;
}

static Checker checkers[] = {
    {"AbuseIPDB", check_abuseIPDB, NULL, NULL, NULL, TRUE},
    {"VirusTotal", check_virustotal, NULL, NULL, NULL, TRUE},
    {"Shodan", check_shodan, NULL, NULL, NULL, TRUE},
    {"IPinfo",check_ipinfo,NULL,NULL,NULL,TRUE},
    {"PulseDive",check_pulsedive,NULL,NULL,NULL,TRUE},
    {"Alien-Vault-OTX",check_alien_vault_otx,NULL,NULL,NULL,TRUE},
    {"IPQS",check_ipqs,NULL,NULL,NULL,TRUE}
};

static int checker_count = sizeof(checkers)/sizeof(checkers[0]);
static int valid_ip(const char *ip){
    struct in_addr addr4;
    struct in6_addr addr6;
    return inet_pton(AF_INET,ip,&addr4)==1||inet_pton(AF_INET6,ip,&addr6)==1;
}
static void clear_labels(){
	for (int i=0;i<checker_count;i++){
		gtk_label_set_text(GTK_LABEL(checkers[i].btn),checkers[i].name);
		if (checkers[i].last_result){
			free(checkers[i].last_result);
			checkers[i].last_result=NULL;
		}
	}
}
static GtkWidget* make_menu_item(const char *label,GCallback callback,gpointer data) {
	GtkWidget *item=gtk_menu_item_new_with_label(label);
	if (callback)
		g_signal_connect(item,"activate",callback,data);
	return item;
}
static void quits(GtkMenuItem *item,gpointer data){
	g_application_quit(G_APPLICATION(data));
}
static void set_dark(GtkMenuItem *item,gpointer data){
	GtkSettings *settings=gtk_settings_get_default();
	g_object_set(settings,"gtk-application-prefer-dark-theme",TRUE,NULL);
	db_save_setting("theme","dark");
}
static void set_white(GtkMenuItem *item,gpointer data){
	GtkSettings *settings=gtk_settings_get_default();
	g_object_set(settings,"gtk-application-prefer-dark-theme",FALSE,NULL);
	db_save_setting("theme","white");
}
static void *checker_thread(void *arg){
	ThreadArg *a=(ThreadArg *)arg;
	int i=a->index;
	char *cached=db_cache_get(a->ip,checkers[i].name);
	char *result=cached ? cached:checkers[i].fn(a->ip);
	if (!cached && result){
		db_cache_save(a->ip,checkers[i].name,result);
	}
	LabelUpdate *u=malloc(sizeof(LabelUpdate));
	u->label=checkers[i].btn;
	u->text=malloc(256);
	snprintf(u->text,256,"%s: %s",checkers[i].name,result ? result:"error");
	free(result);
	g_idle_add(update_label,u);
	free((char *)a->ip);
	free(a);
	return NULL;
}
static void check_clicked(GtkButton *btn,gpointer data){
	AppWidgets *app_w=(AppWidgets *)data;
	const char *ip=gtk_entry_get_text(GTK_ENTRY(app_w->entry));
	if (!ip || ip[0]=='\0'){
		clear_labels();
		return;
	}
	if (!valid_ip(ip)){
		for (int i=0;i<checker_count;i++){
			char sum[256];
			snprintf(sum,sizeof(sum),"%s: invalid ip",checkers[i].name);
			gtk_label_set_text(GTK_LABEL(checkers[i].btn),sum);
		}
		return;
	}
	pthread_t threads[checker_count];
	for (int i=0;i<checker_count;i++){
		if (!checkers[i].enabled){
			gtk_label_set_text(GTK_LABEL(checkers[i].btn),checkers[i].name);
			continue;
		}
		ThreadArg *a=malloc(sizeof(ThreadArg));
		a->ip=strdup(ip);
		a->index=i;
		pthread_create(&threads[i],NULL,checker_thread,a);
		pthread_detach(threads[i]);
	}
}
static void load_env(){
	FILE *f=fopen(".env","r");
	if (!f){
		return;
	}
	char line[256];
	while (fgets(line,sizeof(line),f)){
		char *eq=strchr(line,'=');
		if (!eq){
			continue;
		}
		*eq=0;
		char *val=eq+1;
		val[strcspn(val,"\n")]=0;
		setenv(line,val,0);
	}
	fclose(f);
}
static void toggle_checker(GtkButton *btn,gpointer data){
	Checker *c=(Checker *)data;
	c->enabled=!c->enabled;
	db_save_checker_state(c->name,c->enabled);
	gtk_button_set_label(btn,c->enabled ? "On": "Off");
}
static void encode_clicked(GtkButton *btn,gpointer data){
	EncodeWidgets *w=(EncodeWidgets  *)data;
	const char *text=gtk_entry_get_text(GTK_ENTRY(w->input));
	char *type=gtk_combo_box_text_get_active_text(GTK_COMBO_BOX_TEXT(w->combo));
	if (!type){
		gtk_entry_set_text(GTK_ENTRY(w->output),"select type");
		return;
	}
	char result[1024]={0};
	if (strcmp(type,"text to hex")==0){
		for (int i=0;text[i];i++){
			char buf[4];
			snprintf(buf,sizeof(buf),"%02x ",(unsigned char)text[i]);
			strncat(result,buf,sizeof(result)-strlen(result)-1);
		}
	} else if (strcmp(type,"rot13 to text")==0 || strcmp(type,"text to rot13")==0){
		for (int i=0;text[i];i++){
			char c=text[i];
			if (c>='a' && c<='z') c=(c -'a'+13) %26 + 'a';
			else if (c>='A' && c<='Z') c=(c-'A'+13)%26+'A';
			result[i]=c;
		}
	} else if (strcmp(type,"hex to text")==0){
		int j=0;
		for (int i=0;text[i] && text[i+1];){
			if (text[i]==' '){i++;continue;}
			char buf[3]={text[i],text[i+1],0};
			char ch=(char)strtol(buf,NULL,16);
			result[j++]=(char)strtol(buf,NULL,16);
			i+=2;
		}
	} else if (strcmp(type,"text to base64")==0){
		gchar *encoded=g_base64_encode((const guchar *)text,strlen(text));
		snprintf(result,sizeof(result),"%s",encoded);
		g_free(encoded);

	}else if (strcmp(type,"base64 to text")==0){
		gsize len;
		guchar *decoded=g_base64_decode(text,&len);
		snprintf(result,sizeof(result),"%.*s",(int)len,decoded);
		g_free(decoded);
	} else if (strcmp(type,"text to binary")==0){
		for (int i=0;text[i];i++){
			char buf[10];
			snprintf(buf,sizeof(buf),"%08b",text[i]);
			strncat(result,buf,sizeof(result)-strlen(result)-1);
		}
	}else if (strcmp(type,"binary to text")==0){
		int j=0;
		for (int i=0;text[i];){
			while(text[i]==' ')i++;continue;
			if (!text[i]) break;
			char buf[9]={0};
			strncpy(buf,text+i,8);
			result[j++]=(char)strtol(buf,NULL,2);
			i+=8;
		}
	} else if (strcmp(type,"text to decimal")==0){
		for (int i=0;text[i];i++){
			char buf[6];
			snprintf(buf,sizeof(buf),"%d ",(unsigned char)text[i]);
			strncat(result,buf,sizeof(result)-strlen(result)-1);
		}
	}
	gtk_entry_set_text(GTK_ENTRY(w->output),result);
	g_free(type);
}

static void show_encode(GtkMenuItem *item,gpointer data){
	gtk_stack_set_visible_child_name(GTK_STACK(data),"encode");
}
static void show_main(GtkWidget *widget,gpointer data){
	gtk_stack_set_visible_child_name(GTK_STACK(data),"main");
}
static void menu_bar(GtkWidget *box,GtkApplication *app,GtkWidget *stack){
	GtkWidget *menubar=gtk_menu_bar_new();

	GtkWidget *file_menu=gtk_menu_new();
	gtk_menu_shell_append(GTK_MENU_SHELL(file_menu),make_menu_item("Quit",G_CALLBACK(quits),app));
	GtkWidget *file_item=gtk_menu_item_new_with_label("File");
	gtk_menu_item_set_submenu(GTK_MENU_ITEM(file_item),file_menu);
	gtk_menu_shell_append(GTK_MENU_SHELL(menubar),file_item);
	GtkWidget *tools_menu=gtk_menu_new();
	gtk_menu_shell_append(GTK_MENU_SHELL(tools_menu),make_menu_item("IP checker",G_CALLBACK(show_main),stack));
	gtk_menu_shell_append(GTK_MENU_SHELL(tools_menu),make_menu_item("Encode/Decode",G_CALLBACK(show_encode),stack));
	GtkWidget *tools_item=gtk_menu_item_new_with_label("Tools");
	GtkWidget *view_menu=gtk_menu_new();
	GtkWidget *view_theme=gtk_menu_new();
	GtkWidget *view_item=gtk_menu_item_new_with_label("View");
	GtkWidget *dark_item=make_menu_item("Dark",G_CALLBACK(set_dark),NULL);
	GtkWidget *white_item=make_menu_item("White",G_CALLBACK(set_white),NULL);
	GtkWidget *theme_item=gtk_menu_item_new_with_label("Theme");
	gtk_menu_item_set_submenu(GTK_MENU_ITEM(theme_item),view_theme);
	gtk_menu_item_set_submenu(GTK_MENU_ITEM(tools_item),tools_menu);
	gtk_menu_item_set_submenu(GTK_MENU_ITEM(view_item),view_menu);

	gtk_menu_shell_append(GTK_MENU_SHELL(menubar),view_item);
	gtk_menu_shell_append(GTK_MENU_SHELL(view_menu),theme_item);
	gtk_menu_shell_append(GTK_MENU_SHELL(menubar),tools_item);
	gtk_menu_shell_append(GTK_MENU_SHELL(view_theme),dark_item);
	gtk_menu_shell_append(GTK_MENU_SHELL(view_theme),white_item);

	gtk_box_pack_start(GTK_BOX(box),menubar,FALSE,FALSE,0);	
}
static void activate(GtkApplication *app,gpointer data){
	AppWidgets *w=(AppWidgets *)data;
	GtkWidget *window=gtk_application_window_new(app);
	GtkWidget *box=gtk_box_new(GTK_ORIENTATION_VERTICAL,10);
	GtkWidget *button=gtk_button_new_with_label("check");
	g_signal_connect(button,"clicked",G_CALLBACK(check_clicked),w);
	GtkWidget *stack=gtk_stack_new();

	gtk_window_set_title(GTK_WINDOW(window),"threat intel");
	gtk_window_set_default_size(GTK_WINDOW(window),500,400);
	char *theme=db_get_setting("theme");
	if (theme){
		gboolean dark=strcmp(theme,"dark")==0;
		g_object_set(gtk_settings_get_default(),"gtk-application-prefer-dark-theme",dark,NULL);
		free(theme);
	}
	w->entry=gtk_entry_new();
	w->label=gtk_label_new("");
	gtk_box_pack_start(GTK_BOX(box),w->entry,FALSE,FALSE,5);
	gtk_box_pack_start(GTK_BOX(box),button,FALSE,FALSE,5);
	gtk_box_pack_start(GTK_BOX(box),w->label,FALSE,FALSE,5);
	gtk_stack_add_named(GTK_STACK(stack),box,"main");
	for (int i=0; i<checker_count;i++){
		checkers[i].enabled=db_get_checker_state(checkers[i].name);
		GtkWidget *frame=gtk_frame_new(NULL);
		GtkWidget *row=gtk_box_new(GTK_ORIENTATION_HORIZONTAL,0);
		gtk_container_add(GTK_CONTAINER(frame),row);
		checkers[i].btn=gtk_label_new(checkers[i].name);
		gtk_label_set_xalign(GTK_LABEL(checkers[i].btn),0);
		GtkWidget *toggle=gtk_button_new_with_label("On");
		gtk_button_set_label(GTK_BUTTON(toggle),checkers[i].enabled?"On":"Off");
		checkers[i].check=toggle;
		g_signal_connect(toggle,"clicked",G_CALLBACK(toggle_checker),&checkers[i]);
		gtk_box_pack_start(GTK_BOX(row),checkers[i].btn,TRUE,TRUE,3);
		gtk_box_pack_end(GTK_BOX(row),toggle,FALSE,FALSE,2);
		gtk_box_pack_start(GTK_BOX(box),frame,FALSE,FALSE,2);
	}
	EncodeWidgets *ew=malloc(sizeof(EncodeWidgets));
	g_signal_connect_swapped(window,"destroy",G_CALLBACK(free),ew);
	GtkWidget *encode_box=gtk_box_new(GTK_ORIENTATION_VERTICAL,10);
	GtkWidget *top_row=gtk_box_new(GTK_ORIENTATION_HORIZONTAL,10);
	GtkWidget *start_encode_btn=gtk_button_new_with_label("start");
	GtkWidget *vbox=gtk_box_new(GTK_ORIENTATION_VERTICAL,0);
	menu_bar(vbox,app,stack);
	gtk_box_pack_start(GTK_BOX(vbox),stack,TRUE,TRUE,0);
	gtk_container_add(GTK_CONTAINER(window),vbox);
	ew->combo=gtk_combo_box_text_new();
	gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(ew->combo),"text to hex");
	gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(ew->combo),"hex to text");
	gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(ew->combo),"text to rot13");
	gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(ew->combo),"rot13 to text");
	gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(ew->combo),"text to base64");
	gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(ew->combo),"base64 to text");
	gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(ew->combo),"text to binary");
	gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(ew->combo),"binary to text");
	gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(ew->combo),"text to decimal");
	g_signal_connect(start_encode_btn,"clicked",G_CALLBACK(encode_clicked),ew);
	gtk_box_pack_start(GTK_BOX(top_row),start_encode_btn,FALSE,FALSE,5);
	gtk_box_pack_end(GTK_BOX(top_row),ew->combo,FALSE,FALSE,5);
	gtk_combo_box_set_active(GTK_COMBO_BOX(ew->combo), 0);
	ew->input=gtk_entry_new();
	gtk_entry_set_placeholder_text(GTK_ENTRY(ew->input),"enter text / code: ");
	
	ew->output=gtk_entry_new();
	gtk_editable_set_editable(GTK_EDITABLE(ew->output),FALSE);
	gtk_entry_set_placeholder_text(GTK_ENTRY(ew->output),"output: ");
	gtk_box_pack_start(GTK_BOX(encode_box),top_row,FALSE,FALSE,5);
	gtk_box_pack_start(GTK_BOX(encode_box),ew->input,FALSE,FALSE,5);
	gtk_box_pack_start(GTK_BOX(encode_box),ew->output,TRUE,TRUE,5);
	gtk_stack_add_named(GTK_STACK(stack),encode_box,"encode");
	
	gtk_widget_show_all(window);
}
int main(int argc,char **argv){
	load_env();
	db_init();
	AppWidgets widgets={0};
	
	GtkApplication *app=gtk_application_new("com.threatintel",0);
	g_signal_connect(app,"activate",G_CALLBACK(activate),&widgets);
	int status=g_application_run(G_APPLICATION(app),argc,argv);
	g_object_unref(app);
	return status;
}
