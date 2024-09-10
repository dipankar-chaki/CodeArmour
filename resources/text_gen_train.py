import pandas as pd
import numpy as np
from transformers import RobertaTokenizer, T5ForConditionalGeneration, T5Config, AutoModelForSeq2SeqLM, AutoTokenizer, get_linear_schedule_with_warmup
from torch.utils.data import DataLoader, Dataset, RandomSampler, SequentialSampler
import torch
import torch.optim as optim
from tqdm import tqdm
import logging
import os
import spacy

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class Args:
    def __init__(self):
        self.train_data_file = '/content/drive/MyDrive/9900training/train.csv'
        self.eval_data_file = '/content/drive/MyDrive/9900training/val.csv'
        self.test_data_file = '/content/drive/MyDrive/9900training/test.csv'
        self.block_size = 512
        self.train_batch_size = 8
        self.val_batch_size = 8
        self.epochs = 1
        # # quick test
        # self.sample_size = 50

args = Args()

model = AutoModelForSeq2SeqLM.from_pretrained('Salesforce/codet5-base-multi-sum')
tokenizer = AutoTokenizer.from_pretrained('Salesforce/codet5-base-multi-sum')

device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
model.to(device)


class InputFeatures(object):
    def __init__(self, input_tokens, input_ids, descs):
        self.input_tokens = input_tokens
        self.input_ids = input_ids
        self.descs = descs

def convert_examples_to_features(func, desc, tokenizer, args):
    source_tokens = tokenizer.tokenize(str(func))[:args.block_size-2]
    # deleted that part because we dont know the details of t5 tokenizer, that 
    # is particularlly for codebert
    source_ids = tokenizer.convert_tokens_to_ids(source_tokens)
    padding_length = args.block_size - len(source_ids)
    source_ids += [tokenizer.pad_token_id] * padding_length
    return InputFeatures(source_tokens, source_ids, str(desc))

class CodeToTextDataset(Dataset):
    def __init__(self, tokenizer, args, file_type):
        if file_type == "train":
            file_path = args.train_data_file
        elif file_type == "eval":
            file_path = args.eval_data_file
        elif file_type == "test":
            file_path = args.test_data_file

        self.examples = []
        df = pd.read_csv(file_path)
        # quick testing
        # df = pd.read_csv(file_path).sample(n=args.sample_size)
        funcs = df["vulnerable_code"].tolist()
        descs = df["Explanation_of_Vulnerability_In_Context"].tolist()
        for i in tqdm(range(len(funcs)), desc="Loading data"):
            self.examples.append(convert_examples_to_features(funcs[i],descs[i], tokenizer, args))
        if file_type == "train":
            for example in self.examples[:3]:
                logger.info("*** Example ***")
                logger.info("desc: {}".format(example.descs))
                logger.info("input_tokens: {}".format([x.replace('\u0120','_') for x in example.input_tokens]))
                logger.info("input_ids: {}".format(' '.join(map(str, example.input_ids))))

    def __len__(self):
        return len(self.examples)

    def __getitem__(self, idx):
        example = self.examples[idx]
        return {
            'input_ids': torch.tensor(example.input_ids, dtype=torch.long),
            'desc': torch.tensor(tokenizer.encode(example.descs, padding='max_length', truncation=True, max_length=args.block_size), dtype=torch.long),
        }

def train(train_dataset, model, args, tokenizer):
    train_sampler = RandomSampler(train_dataset)
    train_dataloader = DataLoader(train_dataset, sampler=train_sampler, batch_size=args.train_batch_size, num_workers=0)

    optimizer = optim.AdamW(model.parameters(), lr=5e-5)
    total_steps = len(train_dataloader) * args.epochs
    scheduler = get_linear_schedule_with_warmup(optimizer, num_warmup_steps=0, num_training_steps=total_steps)

    for epoch in range(args.epochs):
        model.train()
        for batch in train_dataloader:
            input_ids = batch['input_ids'].to(device)
            descs = batch['desc'].to(device)
            
            outputs = model(input_ids=input_ids, labels=descs)
            loss = outputs.loss
            
            optimizer.zero_grad()
            loss.backward()
            optimizer.step()
            scheduler.step()
            
            print(f'Epoch: {epoch}, Loss: {loss.item()}')
    model_to_save = model.module if hasattr(model,'module') else model 
    torch.save(model_to_save.state_dict(), '/content/drive/MyDrive/9900training/custom_train_t5.bin')


def test(test_dataset, model, tokenizer, args):
    test_sampler = SequentialSampler(test_dataset)
    test_dataloader = DataLoader(test_dataset, sampler=test_sampler, batch_size=1, num_workers=0)

    model.eval()
    total_loss = 0
    for batch in tqdm(test_dataloader, desc="Testing"):
        input_ids = batch['input_ids'].to(device)
        true_desc = batch['desc'].to(device)

        with torch.no_grad():
            outputs = model.generate(input_ids=input_ids, max_length=args.block_size)

        predicted_desc = tokenizer.decode(outputs[0], skip_special_tokens=True)
        true_desc_decoded = tokenizer.decode(true_desc[0], skip_special_tokens=True)

        logger.info(f"True Description: {true_desc_decoded}")
        logger.info(f"Predicted Description: {predicted_desc}")
        print(f"True Description: {true_desc_decoded}")
        print(f"Predicted Description: {predicted_desc}")    


def test_model(test_dataset, tokenizer, args):
    path_to_model = '/content/drive/MyDrive/9900training/custom_train_t5.bin'
    model.load_state_dict(torch.load(path_to_model))
    test_sampler = SequentialSampler(test_dataset)
    test_dataloader = DataLoader(test_dataset, sampler=test_sampler, batch_size=1, num_workers=0)

    model.eval()
    total_loss = 0
    for batch in tqdm(test_dataloader, desc="Testing"):
        input_ids = batch['input_ids'].to(device)
        true_desc = batch['desc'].to(device)

        with torch.no_grad():
            outputs = model.generate(input_ids=input_ids, max_length=args.block_size)

        predicted_desc = tokenizer.decode(outputs[0], skip_special_tokens=True)
        true_desc_decoded = tokenizer.decode(true_desc[0], skip_special_tokens=True)

        logger.info(f"True Description: {true_desc_decoded}")
        logger.info(f"Predicted Description: {predicted_desc}")
        print(f"True Description: {true_desc_decoded}")
        print(f"Predicted Description: {predicted_desc}")   

def evaluate(val_dataset, model, args, tokenizer):
    val_sampler = SequentialSampler(val_dataset)
    val_dataloader = DataLoader(val_dataset, sampler=val_sampler, batch_size=args.val_batch_size, num_workers=0)

    model.eval()
    total_loss = 0
    for batch in val_dataloader:
        input_ids = batch['input_ids'].to(device)
        descs = batch['desc'].to(device)
        
        with torch.no_grad():
            outputs = model(input_ids=input_ids, labels=descs)
            loss = outputs.loss
            total_loss += loss.item()

    print(f'Validation Loss: {total_loss / len(val_dataloader)}')

def generate_text(model, tokenizer, code, max_len=512):
    model.eval()
    input_enc = tokenizer(code, max_length=max_len, padding='max_length', truncation=True, return_tensors="pt")
    input_ids = input_enc['input_ids'].to(device)
    
    with torch.no_grad():
        outputs = model.generate(input_ids=input_ids, max_length=max_len)
    
    return tokenizer.decode(outputs[0], skip_special_tokens=True)

train_dataset = CodeToTextDataset(tokenizer, args, 'train')
train(train_dataset, model, args, tokenizer)

test_dataset = CodeToTextDataset(tokenizer, args, 'test')
test(test_dataset, model, tokenizer, args)

val_dataset = CodeToTextDataset(tokenizer, args, 'eval')
evaluate(val_dataset, model, args, tokenizer)

# test_dataset = CodeToTextDataset(tokenizer, args, 'test')
# test_model(test_dataset, tokenizer, args)